import ctypes
import os
import logging

# Configurazione logging di base se eseguito standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

class PQVerifier:
    """
    Wrapper per la libreria C che verifica le firme PQ composite (Aurora provider di openssl).
    """
    
    def __init__(self, lib_path):
        """
        Inizializza il wrapper caricando la libreria condivisa .so
        :param lib_path: Percorso assoluto al file libpq_wrapper.so (o aurora_wrapper.so)
        """
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Libreria C non trovata al percorso: {lib_path}")
        
        try:
            # --- CONFIGURAZIONE CRITICA DEL CARICAMENTO ---
            # È necessario usare RTLD_DEEPBIND (disponibile su Linux) per forzare il wrapper
            # a risolvere i propri simboli (linkati staticamente alla tua OpenSSL custom)
            # PRIMA di guardare ai simboli globali (la OpenSSL di sistema caricata da Python).
            # Senza questo, il wrapper userebbe le funzioni della OpenSSL vecchia di sistema e fallirebbe.
            
            dl_flags = ctypes.RTLD_GLOBAL
            if hasattr(os, 'RTLD_DEEPBIND'):
                dl_flags |= os.RTLD_DEEPBIND
                logger.debug("Utilizzo flag RTLD_DEEPBIND per isolamento simboli OpenSSL.")
            
            # Carica la libreria dinamica con i flag specifici
            self.lib = ctypes.CDLL(lib_path, mode=dl_flags)
            
            # Configura la firma della funzione C:
            # int verify_certificate_file(const char* target_cert_path, const char* ca_cert_path)
            self.lib.verify_certificate_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            self.lib.verify_certificate_file.restype = ctypes.c_int
            
            logger.info("Libreria PQ Wrapper caricata correttamente da %s", lib_path)
            
        except OSError as e:
            logger.error("Impossibile caricare la libreria PQ Wrapper: %s", e)
            raise

    def verify_certificate(self, target_cert_path: str, ca_cert_path: str) -> bool:
        """
        Verifica la firma del certificato target contro la CA usando il provider Aurora.
        
        :param target_cert_path: Path del file del certificato da verificare (DER/PEM)
        :param ca_cert_path: Path del file del certificato CA (PEM)
        :return: True se valido, False altrimenti
        """
        # 1. Verifica esistenza file (Python side check)
        if not os.path.exists(target_cert_path):
            logger.error("File certificato target non trovato: %s", target_cert_path)
            return False
        if not os.path.exists(ca_cert_path):
            logger.error("File CA non trovato: %s", ca_cert_path)
            return False

        # 2. Conversione stringhe Python -> Byte string C (UTF-8)
        b_target = target_cert_path.encode('utf-8')
        b_ca = ca_cert_path.encode('utf-8')

        # 3. Chiamata alla funzione C
        # La funzione C gestisce internamente il caricamento del provider Aurora
        try:
            logger.debug("Chiamata funzione C verify_certificate_file...")
            result = self.lib.verify_certificate_file(b_target, b_ca)
            
            if result == 1:
                logger.info("Verifica PQ (C-Level) riuscita per %s", target_cert_path)
                return True
            else:
                logger.warning("Verifica PQ (C-Level) FALLITA per %s (Codice: %d)", target_cert_path, result)
                return False
                
        except Exception as e:
            logger.error("Errore durante l'esecuzione della funzione C verify_certificate_file: %s", e)
            return False

# Esempio di utilizzo standalone
if __name__ == "__main__":
    # Configura i percorsi per il test rapido
    WRAPPER_PATH = "/usr/local/lib/aurora_wrapper.so"
    CA_PATH = "/home/ubuntu/trust-manager/agents-pki/qubip-tls-ca-cert.pem"
    TARGET_PATH = "/home/ubuntu/trust-manager/agents-pki/ebano-cert.der"
    AURORA_PROVIDER_DIR = "/home/ubuntu/quantumsafe_openssl/build/lib64"

    print(f"--- Test PQ Auth Wrapper ---")
    
    # Imposta l'ambiente per il test standalone se necessario
    if "OPENSSL_MODULES" not in os.environ:
        os.environ["OPENSSL_MODULES"] = AURORA_PROVIDER_DIR
        print(f"Env: OPENSSL_MODULES impostato a {AURORA_PROVIDER_DIR}")

    try:
        verifier = PQVerifier(WRAPPER_PATH)
        is_valid = verifier.verify_certificate(TARGET_PATH, CA_PATH)
        
        if is_valid:
            print(f"\n[SUCCESS] Il certificato {TARGET_PATH} è VALIDO.")
        else:
            print(f"\n[FAILURE] Il certificato {TARGET_PATH} NON è valido.")
    except Exception as e:
        print(f"\n[ERROR] Eccezione durante il test: {e}")