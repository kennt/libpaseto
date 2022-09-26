#include "paseto.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v4_LOCAL_KEYBYTES == crypto_generichash_blake2b_KEYBYTES,
        "KEYBYTES mismatch");


static const uint8_t header[] = "v4.local.";
static const size_t header_len = sizeof(header) - 1;
static const size_t mac_len = 32;
static const uint8_t info_enc[] = "paseto-encryption-key";
static const size_t info_enc_len = sizeof(info_enc) - 1;
static const uint8_t info_auth[] = "paseto-auth-key-for-aead";
static const size_t info_auth_len = sizeof(info_auth) - 1;

/* this is the longer of info_enc_len and info_auth_len */
static const size_t info_len = info_auth_len;

bool paseto_v4_local_load_key_hex(
        uint8_t key[paseto_v4_LOCAL_KEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v4_LOCAL_KEYBYTES, key_hex);
}


bool paseto_v4_local_load_key_base64(
        uint8_t key[paseto_v4_LOCAL_KEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v4_LOCAL_KEYBYTES, key_base64);
}


void default_v4_generate_nonce(
        uint8_t nonce[paseto_v4_LOCAL_NONCEBYTES]) {
    randombytes_buf(nonce, paseto_v4_LOCAL_NONCEBYTES);
}

char *paseto_v4_local_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v4_LOCAL_KEYBYTES],
        const uint8_t *footer, size_t footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len,
        const uint8_t *nonce_in, size_t nonce_in_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;
    if (!implicit_assertion) implicit_assertion_len = 0;
    if (!implicit_assertion_len) implicit_assertion = NULL;
    if (!nonce_in) nonce_in_len = 0;
    if (!nonce_in_len) nonce_in = NULL;
    if (nonce_in_len && nonce_in_len != paseto_v4_LOCAL_NONCEBYTES)
    {
        errno = EINVAL;
        return NULL;
    }

    /* #1. Check for local key */
    /* #2. Set header to "v4.local." */

    /* #3. Generate 32 bytes for the nonce */
    size_t to_encode_len = paseto_v4_LOCAL_NONCEBYTES +
                           message_len +
                           mac_len;  /* MAC length */
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode)
    {
        errno = ENOMEM;
        return NULL;        
    }
    uint8_t * nonce = to_encode;
    size_t nonce_len = paseto_v4_LOCAL_NONCEBYTES;
    if (nonce_in)
    {
        memcpy(nonce, nonce_in, paseto_v4_LOCAL_NONCEBYTES);
        nonce_len = paseto_v4_LOCAL_NONCEBYTES;
    }
    else
    {
        default_v4_generate_nonce(nonce);
        nonce_len = paseto_v4_LOCAL_NONCEBYTES;
    }

    // #4. split the keys
    uint8_t hashed[56];
    uint8_t tmp_mess[nonce_len + info_len];
    memcpy(tmp_mess, info_enc, info_enc_len);
    memcpy(tmp_mess+info_enc_len, nonce, nonce_len);
    crypto_generichash(hashed, 56,
        tmp_mess, info_enc_len + nonce_len,
        key, paseto_v4_LOCAL_KEYBYTES);

    uint8_t enc_key[32];
    uint8_t counter_nonce[24];
    memcpy(enc_key, hashed, sizeof(enc_key));
    memcpy(counter_nonce, hashed+sizeof(enc_key), sizeof(counter_nonce));

    uint8_t auth_key[32];
    memcpy(tmp_mess, info_auth, info_auth_len);
    memcpy(tmp_mess+info_auth_len, nonce, nonce_len);
    crypto_generichash(auth_key, sizeof(auth_key),
        tmp_mess, info_auth_len + nonce_len,
        key, paseto_v4_LOCAL_KEYBYTES);


    /* #5. Encrypt using XChaCha20 using enc_key and counter_nonce */
    uint8_t *ciphertext = to_encode + nonce_len;
    size_t ciphertext_len = message_len;
    crypto_stream_xchacha20_xor(
        ciphertext,
        message, message_len,
        counter_nonce, enc_key);

    /** #6. Pack header, nonce, encrypted data, footer,
      *     and implicit assertion
    **/
    struct pre_auth pa;
    if (!pre_auth_init(&pa, 5,
            header_len +
            nonce_len +
            ciphertext_len + 
            footer_len +
            implicit_assertion_len)) {
        free(ciphertext);
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, nonce_len);
    pre_auth_append(&pa, ciphertext, ciphertext_len);
    pre_auth_append(&pa, footer, footer_len);
    pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
    size_t pre_auth_len = pa.current - pa.base;


    /* #7. Calculate Blake2B-MAC using auth_key */
    uint8_t pae_hash[mac_len];
    crypto_generichash(pae_hash, mac_len,
        pa.base, pre_auth_len,
        auth_key, sizeof(auth_key));

    free(pa.base);

    memcpy(to_encode + nonce_len + ciphertext_len, pae_hash, mac_len);

    /* #8. generate output */ 
    char * output = encode_output(NULL,
                       header, header_len,
                       to_encode, to_encode_len,
                       footer, footer_len);
    if (output == NULL)
    {
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    free(to_encode);

    return output;
}


uint8_t *paseto_v4_local_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v4_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }
    size_t minimum_len = header_len
            + sodium_base64_ENCODED_LEN(
                paseto_v4_LOCAL_NONCEBYTES + mac_len,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1;
    if (strlen(encoded) < minimum_len)
    {
        errno = EINVAL;
        return NULL;
    }

    /* #1. Check keys */
    /* #2. (May) check for an expected footer */
    /* #3. Check the header */
    if (sodium_memcmp(encoded, header, header_len) != 0)
    {
        errno = EINVAL;
        return NULL;
    }
    encoded += header_len;


    /* #4. Decode the payload */
    const size_t encoded_len = strlen(encoded);
    size_t decoded_len;
    uint8_t *decoded = malloc(encoded_len);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    const char *encoded_footer;
    if (sodium_base642bin(
            decoded, encoded_len,
            encoded, encoded_len,
            NULL, &decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    const uint8_t *nonce = decoded;
    size_t nonce_len = paseto_v4_LOCAL_NONCEBYTES;
    const uint8_t *ciphertext = decoded + nonce_len;
    size_t ciphertext_len = decoded_len - nonce_len - mac_len;
    const uint8_t *mac = decoded + nonce_len + ciphertext_len;

    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < paseto_v4_LOCAL_NONCEBYTES + mac_len) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        // use memory after the decoded data for the decoded footer
        decoded_footer = decoded + decoded_len;

        if (sodium_base642bin(
                decoded_footer, encoded_len - decoded_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }

    /* #5. Split the key */
    uint8_t hashed[56];
    uint8_t tmp_mess[nonce_len + info_len];
    memcpy(tmp_mess, info_enc, info_enc_len);
    memcpy(tmp_mess+info_enc_len, nonce, nonce_len);
    crypto_generichash(hashed, 56,
        tmp_mess, info_enc_len + nonce_len,
        key, paseto_v4_LOCAL_KEYBYTES);

    uint8_t enc_key[32];
    uint8_t counter_nonce[24];
    memcpy(enc_key, hashed, sizeof(enc_key));
    memcpy(counter_nonce, hashed+sizeof(enc_key), sizeof(counter_nonce));

    uint8_t auth_key[32];
    memcpy(tmp_mess, info_auth, info_auth_len);
    memcpy(tmp_mess+info_auth_len, nonce, nonce_len);
    crypto_generichash(auth_key, sizeof(auth_key),
        tmp_mess, info_auth_len + nonce_len,
        key, paseto_v4_LOCAL_KEYBYTES);

    /* #6. Build pae */
    struct pre_auth pa;
    if (!pre_auth_init(&pa, 5,
            header_len + nonce_len + 
            ciphertext_len + decoded_footer_len +
            implicit_assertion_len)) {
        free(decoded);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, paseto_v4_LOCAL_NONCEBYTES);
    pre_auth_append(&pa, ciphertext, ciphertext_len);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
    const size_t pre_auth_len = pa.current - pa.base;


    /* #7. Calculate Blake2B-MAC using auth_key */
    uint8_t pae_hash[mac_len];
    crypto_generichash(pae_hash, mac_len,
        pa.base, pre_auth_len,
        auth_key, sizeof(auth_key));

    free(pa.base);

    /* #8. Compare t and t2, reject if not equal */
    if (sodium_memcmp(mac, pae_hash, mac_len) != 0)
    {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    /* #9. Decrypt with XChacha20 */
    uint8_t *plaintext = malloc(ciphertext_len+1);
    if (!plaintext) {
        free(decoded);
        errno = ENOMEM;
        return NULL;
    }
    size_t plaintext_len = ciphertext_len;
    crypto_stream_xchacha20_xor(
        plaintext,
        ciphertext, ciphertext_len,
        counter_nonce, enc_key);

    // include a null terminator for convenience
    plaintext[plaintext_len] = '\0';

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            free(decoded);
            free(plaintext);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(internal_footer, decoded_footer, decoded_footer_len);
        internal_footer[decoded_footer_len] = '\0';
        *footer = internal_footer;
        *footer_len = decoded_footer_len;
    } else {
        if (footer) *footer = NULL;
        if (footer_len) *footer_len = 0;
    }

    free(decoded);

    *message_len = plaintext_len;

    return plaintext;
}
