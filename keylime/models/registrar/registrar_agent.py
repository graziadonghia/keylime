import base64
import hmac
from typing import Optional, List
from sqlalchemy import LargeBinary
import cryptography.x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# Aggiunto l'import per Path, necessario per la lettura del file
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
from keylime.models.base.types.certificate import PQCertificate
from keylime.tpm import tpm2_objects
from keylime.tpm.tpm_main import Tpm

# Aggiungi un import per la gestione ASN.1 grezza
import asn1crypto.x509 as asn1_x509 
from asn1crypto.core import OctetString
from asn1crypto.core import Sequence
from asn1crypto.core import BitString # Import necessario per l'estrazione finale

# NUOVO IMPORT OQS PER GESTIRE LA CRITTOGRAFIA PQ
import oqs # Assumiamo che liboqs-python sia installato
# NUOVO IMPORT CTYPES
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
        
        # CAMPO PQ_CERT CONFIGURATO CORRETTAMENTE CON LA NUOVA CLASSE
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
        # Prova a decodificare Base64 per verificare il formato
            decoded_key = base64.b64decode(pq_key)
        except Exception:
            raise ValueError("Invalid pq_key: not a valid Base64 string")

    def _verify_pq_cert_trust_status(self, target_cert_bytes: bytes) -> bool:
        """
        Verifica la catena di fiducia del certificato PQ (che non ha ancora un oggetto Certificate)
        con il certificato CA statico chiamando un wrapper C di OpenSSL (Aurora).
        """
        CA_CERT_PATH = "/home/ubuntu/trust-manager/agents-pki/qubip-tls-ca-cert.pem"
        LIB_WRAPPER_PATH = "/usr/local/lib/aurora_wrapper.so"
        
        # --- CONFIGURAZIONE AMBIENTE CRITICA (CUSTOM OPENSSL) ---
        # Questo path deve puntare alla cartella build/lib64 della tua installazione custom
        # È comunque utile settarlo qui per il contesto del processo corrente se il wrapper non lo fa
        AURORA_PROVIDER_DIR = "/home/ubuntu/quantumsafe_openssl/build/lib64"
        
        if not os.path.exists(CA_CERT_PATH):
            logger.error("FATAL: Certificato CA non trovato a %s.", CA_CERT_PATH)
            return False

        # Impostazione di sicurezza per l'ambiente
        if "OPENSSL_MODULES" not in os.environ:
            logger.info("Forzatura OPENSSL_MODULES a: %s", AURORA_PROVIDER_DIR)
            os.environ["OPENSSL_MODULES"] = AURORA_PROVIDER_DIR
        
        # Imposta LD_LIBRARY_PATH per sicurezza (anche se wrapper è statico)
        current_ld_path = os.environ.get("LD_LIBRARY_PATH", "")
        if AURORA_PROVIDER_DIR not in current_ld_path:
            os.environ["LD_LIBRARY_PATH"] = f"{AURORA_PROVIDER_DIR}:{current_ld_path}"

        temp_cert_path = None
        try:
            # Scrivi i byte del certificato target su un file temporaneo
            with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as temp_cert:
                temp_cert.write(target_cert_bytes)
                temp_cert_path = temp_cert.name
            
            # Istanzia il wrapper importato e chiama la verifica
            # Nota: Se LIB_WRAPPER_PATH non esiste, PQVerifier solleverà FileNotFoundError
            verifier = PQVerifier(LIB_WRAPPER_PATH)
            
            logger.info("Avvio verifica Trust PQ tramite PQVerifier...")
            is_valid = verifier.verify_certificate(temp_cert_path, CA_CERT_PATH)

            if is_valid:
                 logger.info("Verifica Trust PQ: SUCCESS. Il certificato è firmato correttamente.")
            else:
                 logger.error("Verifica Trust PQ Fallita: FAILURE.")
                 
            return is_valid

        except Exception as e:
            logger.error("ERRORE CRITICO nel processo di verifica PQ (Wrapper): %s", e)
            return False
        finally:
            # 3. Pulizia file temporaneo
            if temp_cert_path and os.path.exists(temp_cert_path):
                try:
                    os.remove(temp_cert_path)
                except OSError:
                    pass


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
        
        # --- LOGICA PQ GESTITA TRAMITE OGGETTO PQCertificate ---
        
        # Recupera l'oggetto PQCertificate (già castato da cast_changes)
        pq_cert_obj = self.changes.get("pq_cert")
        pq_key_list = data.get("pq_key")

        pq_key_from_cert_b64 = None
        pq_key_from_payload_b64 = None
        
        # 1. Chiave da Payload
        if pq_key_list:
            try:
                pq_key_from_payload_bytes = bytes(pq_key_list)
                pq_key_from_payload_b64 = base64.b64encode(pq_key_from_payload_bytes).decode("ascii")
                logger.info("Chiave PQ da Payload (diretta) decodificata.")
            except Exception:
                self._add_error("pq_key", "Invalid key format in payload")

        # 2. Verifica ed Estrazione da Certificato
        if pq_cert_obj:
            logger.info("Processamento Certificato PQ dinamico...")
            CA_PATH = "/home/ubuntu/trust-manager/agents-pki/qubip-tls-ca-cert.pem" # Da config in futuro
            
            # A. Verifica Trust (Delega alla classe PQCertificate)
            if pq_cert_obj.verify_trust(CA_PATH):
                logger.info("Verifica Trust PQ: SUCCESS.")
                # B. Estrazione Chiave (Delega alla classe PQCertificate)
                try:
                    pq_key_from_cert_b64 = pq_cert_obj.extract_public_key()
                    logger.info("Estrazione Chiave PQ: SUCCESS.")
                except ValueError as e:
                    logger.error("Estrazione Chiave PQ Fallita: %s", e)
                    self._add_error("pq_cert", f"Key extraction failed: {e}")
            else:
                logger.error("Verifica Trust PQ: FAILURE (CA check failed).")
                self._add_error("pq_cert", "PQ Certificate Trust verification failed against CA.")

        # 3. Confronto e Assegnazione
        if pq_key_from_cert_b64 and pq_key_from_payload_b64:
            if pq_key_from_cert_b64 == pq_key_from_payload_b64:
                logger.info("MATCH: Chiave Certificato == Chiave Payload.")
                self.pq_key = pq_key_from_cert_b64
                self.pq_algorithm = data.get("pq_algorithm")
            else:
                logger.critical("MISMATCH: Le chiavi non corrispondono!")
                self._add_error("pq_key", "Key mismatch between certificate and payload")
                self.pq_key = None
        
        elif pq_key_from_cert_b64:
            if not self.has_errors("pq_cert"): # Usa helper interno se disponibile o controlla self._errors
                logger.warning("Uso chiave da certificato (payload mancante).")
                self.pq_key = pq_key_from_cert_b64
                self.pq_algorithm = data.get("pq_algorithm")

        elif pq_key_from_payload_b64:
             # Blocca fallback se la verifica certificato è fallita esplicitamente (campo pq_cert presente ma con errori)
             if self.changes.get("pq_cert") and (self.has_errors("pq_cert") if hasattr(self, 'has_errors') else bool(self._errors.get("pq_cert"))):
                  logger.critical("INTERRUZIONE: Certificato PQ non valido. Blocco fallback.")
                  self.pq_key = None
             else:
                  logger.warning("Uso chiave da payload (certificato mancante).")
                  self.pq_key = pq_key_from_payload_b64
                  self.pq_algorithm = data.get("pq_algorithm")
       
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
            output["pq_cert"] = base64.b64encode(self.pq_cert.public_bytes(Encoding.DER)).decode("utf-8")

        return output