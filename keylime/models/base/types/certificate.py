import base64
import binascii
import io
import os
import ctypes
import tempfile
import logging
from typing import Optional, TypeAlias, Union, Any, List

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder as pyasn1_decoder
from pyasn1.codec.der import encoder as pyasn1_encoder
from pyasn1.error import PyAsn1Error
from pyasn1_modules import pem as pyasn1_pem
from pyasn1_modules import rfc2459 as pyasn1_rfc2459
from sqlalchemy.types import Text

# Import for manual parsing ASN.1 manual PQ
import asn1crypto.x509 as asn1_x509
from asn1crypto.core import Sequence

from keylime.models.base.type import ModelType

logger = logging.getLogger(__name__)

# --- PQ CONFIGURATION CONSTANTS ---
# Make sure this path is correct on your system
LIB_WRAPPER_PATH = "/usr/local/lib/aurora_wrapper.so"
AURORA_PROVIDER_DIR = "/home/ubuntu/quantumsafe_openssl/build/lib64"
ALGO_NAMES_PK_SIZES = {
    "ml-dsa-87": 2592,
    "slh-dsa-shake-256s": 64 
}


class Certificate(ModelType):
    """The Certificate class implements the model type API... (omitted)"""

    IncomingValue: TypeAlias = Union[cryptography.x509.Certificate, bytes, str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def _load_der_cert(self, der_cert_data: bytes) -> cryptography.x509.Certificate:
        try:
            return cryptography.x509.load_der_x509_certificate(der_cert_data)
        except Exception:
            pyasn1_cert = pyasn1_decoder.decode(der_cert_data, asn1Spec=pyasn1_rfc2459.Certificate())[0]
            return cryptography.x509.load_der_x509_certificate(pyasn1_encoder.encode(pyasn1_cert))

    def _load_pem_cert(self, pem_cert_data: str) -> cryptography.x509.Certificate:
        try:
            return cryptography.x509.load_pem_x509_certificate(pem_cert_data.encode("utf-8"))
        except Exception:
            der_data = pyasn1_pem.readPemFromFile(io.StringIO(pem_cert_data))
            pyasn1_cert = pyasn1_decoder.decode(der_data, asn1Spec=pyasn1_rfc2459.Certificate())[0]
            return cryptography.x509.load_der_x509_certificate(pyasn1_encoder.encode(pyasn1_cert))

    def infer_encoding(self, value: IncomingValue) -> Optional[str]:
        if isinstance(value, cryptography.x509.Certificate):
            return "decoded"
        elif isinstance(value, bytes):
            return "der"
        elif isinstance(value, str) and value.startswith("-----BEGIN CERTIFICATE-----"):
            return "pem"
        elif isinstance(value, str):
            return "base64"
        else:
            return None

    def asn1_compliant(self, value: IncomingValue) -> Optional[bool]:
        try:
            match self.infer_encoding(value):
                case "decoded":
                    return None
                case "der":
                    cryptography.x509.load_der_x509_certificate(value)  # type: ignore[reportArgumentType, arg-type]
                case "pem":
                    cryptography.x509.load_pem_x509_certificate(value)  # type: ignore[reportArgumentType, arg-type]
                case "base64":
                    der_value = base64.b64decode(value, validate=True)  # type: ignore[reportArgumentType, arg-type]
                    cryptography.x509.load_der_x509_certificate(der_value)
                case _:
                    raise Exception
        except Exception:
            return False
        return True

    def cast(self, value: IncomingValue) -> Optional[cryptography.x509.Certificate]:
        if not value:
            return None
        match self.infer_encoding(value):
            case "decoded":
                return value  # type: ignore[reportReturnType, return-value]
            case "der":
                try:
                    return self._load_der_cert(value)  # type: ignore[reportArgumentType, arg-type]
                except PyAsn1Error as err:
                    raise ValueError(f"value cast to certificate appears DER encoded but cannot be deserialized: {value!r}") from err
            case "pem":
                try:
                    return self._load_pem_cert(value)  # type: ignore[reportArgumentType, arg-type]
                except PyAsn1Error as err:
                    raise ValueError(f"value cast to certificate appears PEM encoded but cannot be deserialized: '{str(value)}'") from err
            case "base64":
                try:
                    return self._load_der_cert(base64.b64decode(value, validate=True))  # type: ignore[reportArgumentType, arg-type]
                except (binascii.Error, PyAsn1Error) as err:
                    raise ValueError(f"value cast to certificate appears Base64 encoded but cannot be deserialized: '{str(value)}'") from err
            case _:
                raise TypeError(f"value cast to certificate is of type '{value.__class__.__name__}' but should be one of 'str', 'bytes' or 'cryptography.x509.Certificate'")

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid X.509 certificate in PEM format or otherwise encoded using Base64"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        cert = self.cast(value)
        if not cert:
            return None
        return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("utf-8")

    def render(self, value: IncomingValue) -> Optional[str]:
        cert = self.cast(value)
        if not cert:
            return None
        return cert.public_bytes(Encoding.PEM).decode("utf-8")  # type: ignore[no-any-return]

    @property
    def native_type(self) -> type:
        return cryptography.x509.Certificate

class PQVerifier:
    """Internal wrapper for the PQ signature verification C library (Aurora)."""
    def __init__(self, lib_path):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"C library not found: {lib_path}")
        try:
            # Environment Configuration
            if "OPENSSL_MODULES" not in os.environ:
                os.environ["OPENSSL_MODULES"] = AURORA_PROVIDER_DIR
            
            current_ld_path = os.environ.get("LD_LIBRARY_PATH", "")
            if AURORA_PROVIDER_DIR not in current_ld_path:
                os.environ["LD_LIBRARY_PATH"] = f"{AURORA_PROVIDER_DIR}:{current_ld_path}"

            # Caricamento Libreria con RTLD_GLOBAL/DEEPBIND
            dl_flags = ctypes.RTLD_GLOBAL
            if hasattr(os, 'RTLD_DEEPBIND'):
                dl_flags |= os.RTLD_DEEPBIND
            
            self.lib = ctypes.CDLL(lib_path, mode=dl_flags)
            self.lib.verify_certificate_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            self.lib.verify_certificate_file.restype = ctypes.c_int
            logger.info("Aurora wrapper loaded")
        except OSError as e:
            logger.error("Unable to load PQ Wrapper library: %s", e)
            raise

    def verify(self, target_cert_bytes: bytes, ca_path: str) -> bool:
        if not os.path.exists(ca_path):
            logger.error("CA Certificate not found at %s", ca_path)
            return False

        temp_cert_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as temp_cert:
                temp_cert.write(target_cert_bytes)
                temp_cert_path = temp_cert.name
            
            b_target = temp_cert_path.encode('utf-8')
            b_ca = ca_path.encode('utf-8')
            
            logger.debug("PQVerifier: Calling C verify_certificate_file...")
            result = self.lib.verify_certificate_file(b_target, b_ca)
            return result == 1

        except Exception as e:
            logger.error("Error in PQ C-Wrapper verification: %s", e)
            return False
        finally:
            if temp_cert_path and os.path.exists(temp_cert_path):
                try:
                    os.remove(temp_cert_path)
                except OSError:
                    pass

class PQX509Certificate:
    """Python representation of a PQ X.509 certificate."""
    def __init__(self, der_data: bytes):
        self._der_data = der_data
        # Generic ASN.1 validation
        try:
            self._asn1_obj = asn1_x509.Certificate.load(der_data)
        except Exception as e:
            raise ValueError(f"Invalid ASN.1 structure for PQ Certificate: {e}")

    def public_bytes(self) -> bytes:
        return self._der_data

    def verify_trust(self, ca_path: str) -> bool:
        try:
            verifier = PQVerifier(LIB_WRAPPER_PATH)
            return verifier.verify(self._der_data, ca_path)
        except Exception as e:
            logger.error("PQ Trust Verification exception: %s", e)
            return False

    def extract_public_key(self, algorithm_name) -> str:
        try:
            tbs = self._asn1_obj['tbs_certificate']
            # Access by dictionary key rather than fixed index to avoid ASN.1 shifting issues
            spki_container = tbs['subject_public_key_info']
            spki_raw = spki_container.dump()
            spki_seq = Sequence.load(spki_raw)
            
            # Extraction BitString (index 1) and raw content (skipping padding byte)
            raw_bytes = spki_seq[1].contents[1:]
            expected_pq_pk_size = ALGO_NAMES_PK_SIZES[algorithm_name]
            if len(raw_bytes) != expected_pq_pk_size:
                 raise ValueError(f"Size mismatch: got {len(raw_bytes)}, expected {expected_pq_pk_size}")
            
            return base64.b64encode(raw_bytes).decode("ascii")
        except Exception as e:
            logger.error("PQ Key Extraction Failed: %s", e)
            raise ValueError(f"Could not extract PQ public key: {e}")


class PQCertificate(ModelType):
    """Keylime model type for Post-Quantum certificates.
    Saves to DB as Base64 string of DER.
    """
    
    IncomingValue: TypeAlias = Union[PQX509Certificate, bytes, str, list, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def cast(self, value: IncomingValue) -> Optional[PQX509Certificate]:
        if not value:
            return None
        
        if isinstance(value, PQX509Certificate):
            return value
        
        der_data = None
        
        if isinstance(value, bytes):
             der_data = value
        elif isinstance(value, list):
             try:
                 der_data = bytes(value)
             except Exception as e:
                 raise ValueError(f"PQCertificate input list could not be converted to bytes: {e}")
        elif isinstance(value, str):
            # Check if it's sent as raw PEM text directly
            if "-----BEGIN CERTIFICATE-----" in value:
                der_data = value.encode('utf-8')
            else:
                try:
                    # Try to base64 decode it (Agent might have encoded the whole PEM file)
                    der_data = base64.b64decode(value, validate=True)
                except (binascii.Error, ValueError):
                    raise ValueError("PQCertificate input string must be Base64 encoded DER or PEM")
        
        if der_data:
            # If the data contains PEM markers, strip the OpenSSL text and convert to pure DER
            if b"-----BEGIN CERTIFICATE-----" in der_data:
                try:
                    pem_str = der_data.decode('utf-8')
                    # Extract only the base64 payload between the BEGIN and END markers
                    b64_cert = pem_str.split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
                    # Remove any newlines or whitespaces
                    b64_cert = "".join(b64_cert.split())
                    der_data = base64.b64decode(b64_cert)
                except Exception as e:
                    raise ValueError(f"Failed to parse DER from PEM structure: {e}")

            # By this point, der_data is guaranteed to be clean, binary ASN.1 DER
            return PQX509Certificate(der_data)
        
        raise TypeError(f"Unexpected type for PQCertificate: {type(value)}")

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "pq_cert must be a valid PQ X.509 certificate (bytes list or Base64 encoded)"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        cert = self.cast(value)
        if not cert:
            return None
        return base64.b64encode(cert.public_bytes()).decode("utf-8")

    def render(self, value: IncomingValue) -> Optional[str]:
        cert = self.cast(value)
        if not cert:
            return None
        return base64.b64encode(cert.public_bytes()).decode("utf-8")
    
    @property
    def native_type(self) -> type:
        return PQX509Certificate