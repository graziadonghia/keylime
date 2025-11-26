#!/bin/bash

CERT_PATH="/home/ubuntu/trust-manager/agents-pki/ebano-cert.der"
# Dimensione attesa della chiave pubblica MLDSA-87 (2592 byte, basato sull'output l=2593)
EXPECTED_PQ_KEY_SIZE=2592 

# Passo 1: Configurazione OpenSSL
openssl="/home/ubuntu/quantumsafe_openssl/build/bin/openssl"
$openssl version

# Passo 2: Trova l'offset della Subject Public Key Info (SPKI).
# L'offset della BIT STRING che contiene i byte grezzi della chiave è 187.
# ESTRAI SOLO IL NUMERO DI OFFSET (il primo campo).
BIT_STRING_OFFSET=$($openssl asn1parse -inform DER -in "$CERT_PATH" | awk '/^ *187:.*prim: BIT STRING/ {print $1; exit}' | sed 's/:.*//')

if [ -z "$BIT_STRING_OFFSET" ]; then
    echo "Errore: Impossibile trovare l'offset della BIT STRING (chiave pubblica grezza) nel certificato." >&2
    exit 1
fi

echo "BIT STRING Offset trovato: $BIT_STRING_OFFSET"
echo "--- Dati Chiave Pubblica MLDSA-87 (Raw Bytes) ---"

# Passo 3: Estrai il contenuto HEX della BIT STRING utilizzando -strparse e -dump.
# -strparse punta all'inizio del contenuto. -dump forza l'output esadecimale.
# Usiamo 'tr' per rimuovere spazi e newline dall'output di dump.

RAW_KEY_HEX_WITH_PADDING=$($openssl asn1parse -inform DER -in "$CERT_PATH" -strparse "$BIT_STRING_OFFSET" -dump | \
                           grep -vE ':\s*$' | \
                           tr -d ' \n\r' | \
                           sed 's/.*:d=.*:\(.*\)/\1/') # Filtra solo il contenuto HEX

# Se il comando precedente fallisce a causa dell'output non standard, usa questo fallback:
if [[ ! "$RAW_KEY_HEX_WITH_PADDING" =~ ^[0-9a-fA-F]+$ ]]; then
    
    # Tentativo di estrazione più grezzo, estraendo il contenuto binario e convertendo in HEX
    RAW_KEY_BIN_WITH_PADDING=$($openssl asn1parse -inform DER -in "$CERT_PATH" -strparse "$BIT_STRING_OFFSET" -genstr oct)

    if [ -z "$RAW_KEY_BIN_WITH_PADDING" ]; then
        echo "Errore: Impossibile estrarre il contenuto binario grezzo della chiave pubblica. Controllare il percorso." >&2
        # La riga '187 is out of range' che vedi è OpenSSL che fallisce a causa dell'OID PQ sconosciuto.
        # Falliamo qui per non procedere con dati errati.
        exit 1
    fi
    
    # Converti il binario in HEX
    RAW_KEY_HEX_WITH_PADDING=$(echo "$RAW_KEY_BIN_WITH_PADDING" | xxd -p | tr -d '\n\r ')
fi


# Passo 4: Rimuovi il byte di padding (i primi due caratteri HEX)
# RAW_KEY_HEX_WITH_PADDING: [00][Chiave MLDSA-87]
RAW_KEY_HEX_NO_PADDING="${RAW_KEY_HEX_WITH_PADDING:2}" # Rimuove i primi 2 caratteri esadecimali (il byte 00)

echo "Chiave Pubblica MLDSA-87 (Hex, senza byte di padding):"
echo "$RAW_KEY_HEX_NO_PADDING"

# Verifica della lunghezza (opzionale ma utile)
EXPECTED_HEX_LENGTH=$(( $EXPECTED_PQ_KEY_SIZE * 2 ))
ACTUAL_HEX_LENGTH=${#RAW_KEY_HEX_NO_PADDING}
if [ "$ACTUAL_HEX_LENGTH" -ne "$EXPECTED_HEX_LENGTH" ]; then
    echo "ATTENZIONE: La lunghezza HEX è $ACTUAL_HEX_LENGTH, attesi $EXPECTED_HEX_LENGTH caratteri." >&2
fi


echo "--- Chiave Pubblica MLDSA-87 (Base64 per Registrar) ---"
# Decodifica Hex in Binario, poi codifica in Base64
echo "$RAW_KEY_HEX_NO_PADDING" | xxd -r -p | base64 -w 0
echo ""