import base64
import hmac
from typing import Optional, List
from sqlalchemy import LargeBinary
import cryptography.x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pathlib import Path 
import base64
from keylime import cert_utils, config, crypto, keylime_logging
from keylime.models.base import (
    Boolean, 
    Certificate, 
    Dictionary, 
    Integer, 
    OneOf, 
    PersistableModel, 
    String, 
    LargeBinary, 
    da_manager
)
import time
from keylime.models.base.types.certificate import PQCertificate
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import Tpm

import asn1crypto.x509 as asn1_x509 
from asn1crypto.core import OctetString
from asn1crypto.core import Sequence
from asn1crypto.core import BitString # Import necessary for final extraction

import oqs
import ctypes
import os
import tempfile

logger = keylime_logging.init_logging("registrar")

class RegistrarAgent(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("registrarmain")
        cls._id("agent_id", String(80))

        # The endorsement key (EK) of the TPM
        cls._field("ek_tpm", String(500))
        # The endorsement key (EK) certificate used to verify the TPM as genuine
        cls._field("ekcert", Certificate, nullable=True)
        # The attestation key (AK) used by Keylime to prepare TPM quotes
        cls._field("aik_tpm", String(500))
        # The initial attestation key (IAK) used when registering with a DevID
        cls._field("iak_tpm", String(500))
        # The initial attestation key (IAK) certificate used to verify IAK authenticity
        cls._field("iak_cert", Certificate, nullable=True)
        # The signing key used as initial device identity (IDevID) key
        cls._field("idevid_tpm", String(500))
        # The initial device identity (IDevID) certificate used to verify IDevID authenticity
        cls._field("idevid_cert", Certificate, nullable=True)
        # The HMAC key used to verify the response produced by TPM2_ActivateCredential to bind the AK to the EK
        cls._field("key", String(45))
        # Indicates that the AK has successfully been bound to the EK
        cls._field("active", Boolean)

        # The details used to establish connections to the agent when operating in pull mode
        cls._field("ip", String(15), nullable=True)
        cls._field("port", Integer, nullable=True)
        cls._field("mtls_cert", OneOf(Certificate, "disabled"), nullable=True)

        # The pq_key used for the quote wrapping
        cls._field("pq_key", String(5000), nullable=True)

        # The PQ algorithm used for the quote wrapping
        cls._field("pq_algorithm", String(50), nullable=True)
        
        # PQ Cert field
        cls._field("pq_cert", PQCertificate, nullable=True) 

        # The number of times the agent has registered over its lifetime
        cls._field("regcount", Integer)

        # NO LONGER USED:
        # Indicates that the agent is running in a cloud VM and that the EKcert is not available from NVRAM
        cls._field("virtual", Boolean)
        # Information about the cloud VM (including the EKcert obtained out of band from the cloud provider)
        cls._field("provider_keys", Dictionary)

    @classmethod
    def empty(cls):
        agent = super().empty()
        agent.provider_keys = {}
        return agent

    def _check_key_against_cert(self, tpm_key_field, cert_field):
        # If neither key nor certificate is being updated, no need to check
        if tpm_key_field not in self.changes and cert_field not in self.changes:
            return

        # Get key and certificate from the record (either the changed value or the value from the DB)
        tpm_key = self.values.get(tpm_key_field)
        cert = self.values.get(cert_field)

        # If either key or certificate is missing from the record, it is not possible to compare the two
        if not tpm_key or not cert:
            return

        # Convert TPM key structure to a public key object and extract the raw key byte string
        try:
            tpm_pub = tpm2_objects.pubkey_from_tpm2b_public(base64.b64decode(tpm_key, validate=True))
            tpm_pub_bytes = tpm_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        except Exception:
            self._add_error(tpm_key_field, "must be a valid TPM2B_PUBLIC structure")
            return

        # Make sure that the TPM key is either an RSA or EC public key
        if not isinstance(tpm_pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            self._add_error(tpm_key_field, "must contain a valid RSA or EC public key")
            return

        # Extract public key bytes from certificate
        cert_pub = cert.public_key()
        cert_pub_bytes = cert_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        # Check that the public key obtained from the TPM matches the public key contained in the certificate
        if tpm_pub_bytes != cert_pub_bytes:
            self._add_error(tpm_key_field, f"must contain the same public key found in {cert_field}")
            return

    def _check_cert_trust_status(self, cert_field, cert_type=""):
        cert = self.changes.get(cert_field)

        if not cert:
            return

        # This is the directory currently used to trust IAK/IDevID certificates but this will be replaced with a
        # more robust trust store implementation in a subsequent PR
        trust_store = config.get("tenant", "tpm_cert_store")

        if not cert_utils.verify_cert(cert, trust_store, cert_type):
            self._add_error(cert_field, "must contain a certificate issued by a CA present in the trust store")

    def _check_cert_compliance(self, cert_field, raw_cert):
        new_cert = self.changes.get(cert_field)
        old_cert = self.values.get(cert_field)

        # If the certificate field has not been changed, no need to perform check
        if not raw_cert or not new_cert:
            return True

        # If the new certificate value is the same as the old certificate value, no need to perform check
        if (
            isinstance(new_cert, cryptography.x509.Certificate)
            and isinstance(old_cert, cryptography.x509.Certificate)
            and new_cert.public_bytes(Encoding.DER) == old_cert.public_bytes(Encoding.DER)
        ):
            return True

        compliant = Certificate().asn1_compliant(raw_cert)

        if not compliant:
            if config.get("registrar", "malformed_cert_action") == "reject":
                self._add_error(cert_field, Certificate().generate_error_msg(raw_cert))

        return compliant

    def _check_all_cert_compliance(self, data):
        non_compliant_certs = []

        for field_name in ("ekcert", "iak_cert", "idevid_cert", "mtls_cert"):
            if not self._check_cert_compliance(field_name, data.get(field_name)):
                non_compliant_certs.append(f"'{field_name}'")

        if not non_compliant_certs:
            return

        names = ", ".join(non_compliant_certs)
        names = " and".join(names.rsplit(",", 1))

        match config.get("registrar", "malformed_cert_action"):
            case "ignore":
                return
            case "reject":
                logger.error(
                    "Certificate(s) %s may not conform to strict ASN.1 DER encoding rules and were rejected due to "
                    "config ('malformed_cert_action = reject')",
                    names,
                )
            case _:
                logger.warning(
                    "Certificate(s) %s may not conform to strict ASN.1 DER encoding rules and were re-encoded before "
                    "parsing by python-cryptography",
                    names,
                )

    def _bind_ak_to_iak(self, iak_attest, iak_sign):
        # The ak-iak binding should only be verified when either aik_tpm or iak_tpm is changed
        if "aik_tpm" not in self.changes or "iak_tpm" not in self.changes:
            return

        # If one of aik_tpm or iak_tpm is missing from the record, the ak-iak binding cannot be verified so skip
        if not self.aik_tpm or not self.iak_tpm:
            return

        # If the iak_attest and iak_sign values are missing, treat this as an error
        if not iak_attest or not iak_sign:
            self._add_error("aik_tpm", "cannot be bound to the IAK because of a missing 'iak_attest' or 'iak_sign'")

        # Decode Base64 values to binary TPM structures
        aik_tpm = base64.b64decode(self.aik_tpm)
        iak_tpm = base64.b64decode(self.iak_tpm)
        iak_attest = base64.b64decode(iak_attest)
        iak_sign = base64.b64decode(iak_sign)

        # Verify that iak_attest properly contains reference to aik_tpm and that iak_sign is a signature thereover
        # produced by the private key corresponding to iak_tpm
        if not Tpm.verify_aik_with_iak(self.agent_id, aik_tpm, iak_tpm, iak_attest, iak_sign):
            self._add_error("aik_tpm", "cannot be confirmed as having been created by the same TPM as the IAK")

    def _check_ek(self):
        # Check that the EK public keys from the TPM match the public keys contained in the EK certificate
        self._check_key_against_cert("ek_tpm", "ekcert")

        # The current behaviour of the registrar is not to perform any verification of the EK certificate against
        # trusted TPM manufacturer certificates. This responsibility is left to the tenant. A future PR will add
        # a trust store to the registrar at which point the below line will be uncommented
        #
        ## self._check_cert_trust_status("ek_cert")

        # Note: The AK cannot be verified as bound to the EK until the agent receives a challenge and uses the TPM
        # to produce a response (see the self.produce_ak_challenge() and self.verify_ak_response(response) methods).

    def _check_iak_idevid(self, iak_attest, iak_sign):
        # Check that the IAK/IDevID public keys from the TPM match the public keys contained in the IAK/IDevID certs
        self._check_key_against_cert("iak_tpm", "iak_cert")
        self._check_key_against_cert("idevid_tpm", "idevid_cert")
        # Check that the IAK/IDevID certificates are trusted
        self._check_cert_trust_status("iak_cert", "IAK")
        self._check_cert_trust_status("idevid_cert", "IDevID")
        # Check that the AK is bound to the IAK by way of TPM2_Certify
        self._bind_ak_to_iak(iak_attest, iak_sign)

    def _check_root_identity_presence(self):
        tpm_identity = config.get("registrar", "tpm_identity", fallback="default")

        if tpm_identity == "iak_idevid":
            self.validate_required(["iak_tpm", "idevid_tpm"], msg="is required by configuration")
        elif tpm_identity == "ek_cert":
            self.validate_required(["ek_tpm"], msg="is required by configuration")
        else:
            # If tpm_identity == "default" or tpm_identity == "ek_cert_or_iak_idevid" then either EK or IAK/IDevID is
            # allowed as the root identity, so check that either one or the other is present:

            if not self.iak_tpm and not self.ek_tpm:
                self._add_error("iak_tpm", "is required in absence of an EK")

            if not self.idevid_tpm and not self.ek_tpm:
                self._add_error("idevid_tpm", "is required in absence of an EK")

            if not self.ek_tpm and not self.iak_tpm and not self.idevid_tpm:
                self._add_error("ek_tpm", "is required in absence of an IAK and IDevID")

        # If an IAK/IDevID is provided, ensure that IAK/IDevID certificates are also present. This requirement will be
        # dropped when IAK/IDevID registration without including certs is enabled (when web hook functionality is added)
        if self.changes.get("iak_tpm") or self.changes.get("idevid_tpm"):
            self.validate_required(["iak_cert", "idevid_cert"], msg="is required when IDevID/IAK key is provided")

        if self.changes.get("iak_cert") or self.changes.get("idevid_cert"):
            self.validate_required(["iak_tpm", "idevid_tpm"], msg="is required when IDevID/IAK certificate is provided")

        if self.changes.get("ek_cert"):
            self.validate_required(["ek_tpm"], msg="is required when EK certificate is provided")

    def _log_root_identity(self):
        tpm_identity = config.get("registrar", "tpm_identity", fallback="default")

        if self.changes.get("iak_tpm") and self.changes.get("idevid_tpm"):
            if tpm_identity == "ek_cert":
                logger.info("IDevID and IAK received for agent '%s', ignoring", self.agent_id)
            else:
                logger.info("IDevID and IAK received for agent '%s'", self.agent_id)

        if self.changes.get("ek_tpm"):
            if tpm_identity == "iak_idevid":
                logger.info("EK received for agent '%s', ignoring", self.agent_id)
            else:
                logger.info("EK received for agent '%s'", self.agent_id)

    def _prepare_status_flags(self):
        if "ek_tpm" in self.changes or "aik_tpm" in self.changes:
            self.active = False  # pylint: disable=attribute-defined-outside-init

    def _prepare_regcount(self):
        reg_fields = ("ek_tpm", "ekcert", "aik_tpm", "iak_tpm", "iak_cert", "idevid_tpm", "idevid_cert")

        if self.regcount is None:  # pylint: disable=access-member-before-definition
            self.regcount = 0  # pylint: disable=attribute-defined-outside-init

        if any(field in reg_fields for field in self.changes) and self.changes_valid:
            self.regcount += 1

    def _validate_pq_key(self, pq_key: str) -> None:
        if not isinstance(pq_key, str):
            raise ValueError("pq_key must be a str")
        try:
            decoded_key = base64.b64decode(pq_key)
        except Exception:
            raise ValueError("Invalid pq_key: not a valid Base64 string")

    def update(self, data):    
        self.cast_changes(
            data,
            ["agent_id", "ek_tpm", "ekcert", "aik_tpm", "iak_tpm", "iak_cert", "idevid_tpm", "idevid_cert", "ip", "pq_key", "pq_algorithm", "pq_cert"]
            + ["port", "mtls_cert"],
        )

        self._log_root_identity()
        self._check_ek()
        self._check_iak_idevid(data.get("iak_attest"), data.get("iak_sign"))
        self._check_root_identity_presence()
        self._check_all_cert_compliance(data)

        self.validate_required(["aik_tpm"])
        self.validate_base64(["ek_tpm", "aik_tpm", "iak_tpm", "idevid_tpm"])

        self._prepare_status_flags()
        self._prepare_regcount()
        pq_cert_obj = self.changes.get("pq_cert")
        pq_verify_cert_ms = 0.0
        if pq_cert_obj:
            logger.info("PQ certificate received. Algorithm: {}...".format(data.get("pq_algorithm")))
            CA_PATH = config.get("registrar", "pq_ca_cert")
            # --- METRIC START: Cert Verification ---
            t_start = time.perf_counter()
            
            is_trusted = pq_cert_obj.verify_trust(CA_PATH)
            
            t_end = time.perf_counter()
            pq_verify_cert_ms = (t_end - t_start) * 1000
            # --- METRIC END ---

            if is_trusted:
                logger.info("PQ Certificate verification: SUCCESS.")
                try:
                    pq_key_from_cert_b64 = pq_cert_obj.extract_public_key()
                    logger.info("PQ Key extraction: SUCCESS.")
                except ValueError as e:
                    logger.error("PQ Key extraction: FAILURE: %s", e)
                    self._add_error("pq_cert", f"Key extraction failed: {e}")
            else:
                logger.error("PQ Certificate verification: FAILURE (CA check failed).")
                self._add_error("pq_cert", "PQ Certificate Trust verification failed against CA.")

        # --- LOG TO CSV ---
        if pq_verify_cert_ms > 0:
            try:
                csv_path = "/tmp/registrar_metrics.csv"
                write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
                
                with open(csv_path, "a") as f:
                    if write_header:
                        f.write("timestamp,agent_id,pq_algo,metric_type,duration_ms\n")
                    
                    now = int(time.time())
                    algo = data.get("pq_algorithm", "unknown")
                    # Log specifically as 'cert_verify'
                    f.write(f"{now},{self.agent_id},{algo},cert_verify,{pq_verify_cert_ms:.4f}\n")
            except Exception as e:
                logger.error(f"Failed to log metrics: {e}")
            if pq_cert_obj.verify_trust(CA_PATH):
                logger.info("PQ Certificate verification: SUCCESS.")
                # B. Estrazione Chiave (Delega alla classe PQCertificate)
                try:
                    pq_key_from_cert_b64 = pq_cert_obj.extract_public_key()
                    logger.info("PQ Key extraction: SUCCESS.")
                except ValueError as e:
                    logger.error("PQ Key extraction: FAILURE: %s", e)
                    self._add_error("pq_cert", f"Key extraction failed: {e}")
            else:
                logger.error("PQ Certificate verification: FAILURE (CA check failed).")
                self._add_error("pq_cert", "PQ Certificate Trust verification failed against CA.")
       
    def produce_ak_challenge(self):
        if not self.ek_tpm or not self.aik_tpm:
            return None

        ek_tpm = base64.b64decode(self.ek_tpm)
        aik_tpm = base64.b64decode(self.aik_tpm)

        try:
            result = Tpm.encrypt_aik_with_ek(self.agent_id, ek_tpm, aik_tpm)

            if not result:
                return None

        except ValueError:
            return None

        (challenge, key) = result
        self.change("key", key)
        return challenge.decode("utf-8")

    def verify_ak_response(self, response):
        logger.debug("Verifying AK response")
        expected_response = crypto.do_hmac(self.key.encode(), self.agent_id)

        result = hmac.compare_digest(response, expected_response)

        self.change("active", result)
        return result

    def commit_changes(self):
        # Accept changes and write them to the database (unless fields have errors)
        super().commit_changes()

        # Write updated record to a durable attestation (DA) backend if configured
        if da_manager.backend:
            agent_data = {}

            # Prepare all record data to be sent to a DA backend according to each field's data type
            for name, field in self.__class__.fields.items():
                agent_data[name] = field.data_type.da_dump(self.committed.get(name))

            # Write dumped data to DA backend as an "agent data" record
            da_manager.backend.record_create(agent_data, None, None, None)

        # Note: Ideally one would want the DA code in keylime.da to be data agnostic (in the same way as a database
            # engine), so that writing to the DA backend could be handled transparently by PersistableModel. As this isn't
            # the case, it is necessary to override commit_changes and make the record_create call on a case-by-case basis.

    def render(self, only=None):
        if not only:
            only = ["agent_id", "ek_tpm", "ekcert", "aik_tpm", "mtls_cert", "ip", "port", "regcount", "pq_key", "pq_algorithm", "pq_cert"]

            if self.virtual:
                only.append("provider_keys")

        output = super().render(only)

        # When operating in pull mode, ekcert is encoded as Base64 instead of PEM
        if output.get("ekcert"):
            output["ekcert"] = base64.b64encode(self.ekcert.public_bytes(Encoding.DER)).decode("utf-8")

        # Codifica Base64 del certificato PQ
        if output.get("pq_cert"):
            output["pq_cert"] = base64.b64encode(self.pq_cert.public_bytes()).decode("utf-8")

        return output