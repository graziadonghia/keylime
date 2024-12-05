#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DEBUG 0
int verify_signature(const uint8_t* message, size_t quote_len, const uint8_t* signature, size_t signature_len, const uint8_t* public_key) {
    // Controlla se l'algoritmo SPHINCS+ è abilitato
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_sphincs_shake_256s_simple)) {
        fprintf(stderr, "Algoritmo SPHINCS+ non disponibile!\n");
        return -1; // Errore
    }

    // Inizializza la struttura per SPHINCS+
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256s_simple);
    if (sig == NULL) {
        fprintf(stderr, "Errore nella creazione della struttura di verifica!\n");
        return -1; // Errore
    }
#if DEBUG
    fprintf(stdout, "Chiave pubblica: ");
    for (size_t i = 0; i < sig->length_public_key; i++) {
        fprintf(stderr, "%02X", public_key[i]);
    }
    fprintf(stdout, "\n");
    // Verifica della firma
    fprintf(stdout, "QUOTE LENGTH = %ld\n", strlen(message));
    fprintf(stdout, "SIGNATURE LENGTH = %ld %ld\n", signature_len, sig->length_signature);
#endif
    if (OQS_SIG_verify(sig, message, quote_len, signature, sig->length_signature, public_key)!= OQS_SUCCESS) {

        fprintf(stderr, "Firma non valida\n");
    
        return -1; // Firma non valida
    }
    return 0; // Firma valida
}
