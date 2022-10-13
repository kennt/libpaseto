#include "paseto.h"
#include "paserk.h"
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

    size_t to_encode_len = paseto_v4_LOCAL_NONCEBYTES +
                           message_len +
                           mac_len;  /* MAC length */
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode)
    {
        errno = ENOMEM;
        return NULL;        
    }

    /* #1. Check for local key */
    /* #2. Set header to "v4.local." */
    /* #3. Generate 32 bytes for the nonce */
    uint8_t * nonce = to_encode;
    size_t nonce_len = paseto_v4_LOCAL_NONCEBYTES;

    {
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
    }

    // #4. split the keys
    uint8_t enc_key[32];
    uint8_t counter_nonce[24];
    uint8_t auth_key[32];

    {
        uint8_t hashed[56];
        uint8_t tmp_mess[nonce_len + info_len];
        memcpy(tmp_mess, info_enc, info_enc_len);
        memcpy(tmp_mess+info_enc_len, nonce, nonce_len);
        crypto_generichash(hashed, 56,
            tmp_mess, info_enc_len + nonce_len,
            key, paseto_v4_LOCAL_KEYBYTES);

        memcpy(enc_key, hashed, sizeof(enc_key));
        memcpy(counter_nonce, hashed+sizeof(enc_key), sizeof(counter_nonce));

        memcpy(tmp_mess, info_auth, info_auth_len);
        memcpy(tmp_mess+info_auth_len, nonce, nonce_len);
        crypto_generichash(auth_key, sizeof(auth_key),
            tmp_mess, info_auth_len + nonce_len,
            key, paseto_v4_LOCAL_KEYBYTES);

        sodium_memzero(hashed, sizeof(hashed));
        sodium_memzero(tmp_mess, sizeof(tmp_mess));
    }

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
    size_t pre_auth_len;

    {
        if (!pre_auth_init(&pa, 5,
                header_len +
                nonce_len +
                ciphertext_len + 
                footer_len +
                implicit_assertion_len)) {
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(to_encode, to_encode_len);
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
        pre_auth_len = pa.current - pa.base;
    }

    /* #7. Calculate Blake2B-MAC using auth_key */
    uint8_t pae_hash[mac_len];
    crypto_generichash(pae_hash, mac_len,
        pa.base, pre_auth_len,
        auth_key, sizeof(auth_key));

    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    memcpy(to_encode + nonce_len + ciphertext_len, pae_hash, mac_len);

    /* #8. generate output */ 
    char * output = encode_output(NULL,
                       header, header_len,
                       to_encode, to_encode_len,
                       footer, footer_len);

    sodium_memzero(to_encode, to_encode_len);
    free(to_encode);
    
    if (output == NULL)
    {
        sodium_memzero(auth_key, sizeof(auth_key));
        sodium_memzero(counter_nonce, sizeof(counter_nonce));
        sodium_memzero(enc_key, sizeof(enc_key));
        errno = EINVAL;
        return NULL;
    }

    sodium_memzero(auth_key, sizeof(auth_key));
    sodium_memzero(counter_nonce, sizeof(counter_nonce));
    sodium_memzero(enc_key, sizeof(enc_key));
    return output;
}


uint8_t *paseto_v4_local_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v4_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len)
{
    if (footer) *footer = NULL;
    if (footer_len) *footer_len = 0;

    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }
    size_t minimum_len = header_len
            + BIN_TO_BASE64_MAXLEN(paseto_v4_LOCAL_NONCEBYTES + mac_len) - 1;
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
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;
    uint8_t * decoded;

    uint8_t *nonce;
    size_t nonce_len;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *mac;
    size_t body_len = 0;

    {
        uint8_t *body = NULL;

        decoded = decode_input(
                     encoded, encoded_len,
                     &body, &body_len,
                     &decoded_footer, &decoded_footer_len);
        if (!decoded)
        {
            errno = EINVAL;
            return NULL;
        }

        nonce = body;
        nonce_len = paseto_v4_LOCAL_NONCEBYTES;

        ciphertext = body + nonce_len;
        ciphertext_len = body_len - nonce_len - mac_len;

        mac = body + nonce_len + ciphertext_len;
    }

    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < paseto_v4_LOCAL_NONCEBYTES + mac_len) {
        sodium_memzero(decoded_footer, decoded_footer_len);
        sodium_memzero(decoded, body_len);
        free(decoded_footer);
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    /* #5. Split the key */
    uint8_t enc_key[32];
    uint8_t counter_nonce[24];
    uint8_t auth_key[32];

    {
        uint8_t hashed[56];
        uint8_t tmp_mess[nonce_len + info_len];
        memcpy(tmp_mess, info_enc, info_enc_len);
        memcpy(tmp_mess+info_enc_len, nonce, nonce_len);
        crypto_generichash(hashed, 56,
            tmp_mess, info_enc_len + nonce_len,
            key, paseto_v4_LOCAL_KEYBYTES);

        memcpy(enc_key, hashed, sizeof(enc_key));
        memcpy(counter_nonce, hashed+sizeof(enc_key), sizeof(counter_nonce));

        memcpy(tmp_mess, info_auth, info_auth_len);
        memcpy(tmp_mess+info_auth_len, nonce, nonce_len);
        crypto_generichash(auth_key, sizeof(auth_key),
            tmp_mess, info_auth_len + nonce_len,
            key, paseto_v4_LOCAL_KEYBYTES);

        sodium_memzero(hashed, sizeof(hashed));
        sodium_memzero(tmp_mess, sizeof(tmp_mess));
    }

    /* #6. Build pae */
    struct pre_auth pa;
    size_t pre_auth_len;

    {
        if (!pre_auth_init(&pa, 5,
                header_len + nonce_len +
                ciphertext_len + decoded_footer_len +
                implicit_assertion_len)) {
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(decoded_footer);
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, nonce, paseto_v4_LOCAL_NONCEBYTES);
        pre_auth_append(&pa, ciphertext, ciphertext_len);
        pre_auth_append(&pa, decoded_footer, decoded_footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    /* #7. Calculate Blake2B-MAC using auth_key */
    uint8_t pae_hash[mac_len];

    {
        crypto_generichash(pae_hash, mac_len,
            pa.base, pre_auth_len,
            auth_key, sizeof(auth_key));
    }
    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    /* #8. Compare t and t2, reject if not equal */
    if (sodium_memcmp(mac, pae_hash, mac_len) != 0)
    {
        sodium_memzero(pae_hash, sizeof(pae_hash));
        sodium_memzero(auth_key, sizeof(auth_key));
        sodium_memzero(counter_nonce, sizeof(counter_nonce));
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(decoded_footer, decoded_footer_len);
        sodium_memzero(decoded, body_len);
        free(decoded_footer);
        free(decoded);
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(pae_hash, sizeof(pae_hash));

    /* #9. Decrypt with XChacha20 */
    uint8_t *plaintext;
    size_t plaintext_len = ciphertext_len;

    {
        plaintext = malloc(ciphertext_len+1);
        if (!plaintext) {
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(decoded_footer);
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        crypto_stream_xchacha20_xor(
            plaintext,
            ciphertext, ciphertext_len,
            counter_nonce, enc_key);
    }

    // include a null terminator for convenience
    plaintext[plaintext_len] = '\0';

    if (footer)
        *footer = decoded_footer;
    else
    {
        sodium_memzero(decoded_footer, decoded_footer_len);
        free(decoded_footer);
    }

    if (footer_len)
        *footer_len = decoded_footer_len;

    sodium_memzero(decoded, body_len);
    free(decoded);

    *message_len = plaintext_len;

    sodium_memzero(auth_key, sizeof(auth_key));
    sodium_memzero(counter_nonce, sizeof(counter_nonce));
    sodium_memzero(enc_key, sizeof(enc_key));

    return plaintext;
}


static const char paserk_local[] = "k4.local.";
static const size_t paserk_local_len = sizeof(paserk_local) - 1;
static const char paserk_lid[] = "k4.lid.";
static const size_t paserk_lid_len = sizeof(paserk_lid) - 1;
static const char paserk_seal[] = "k4.seal.";
static const size_t paserk_seal_len = sizeof(paserk_seal) - 1;
static const char paserk_local_wrap[] = "k4.local-wrap.pie.";
static const size_t paserk_local_wrap_len = sizeof(paserk_local_wrap) - 1;
static const char paserk_local_pw[] = "k4.local-pw.";
static const size_t paserk_local_pw_len = sizeof(paserk_local_pw) - 1;


char * paseto_v4_local_key_to_paserk(
    uint8_t key[paseto_v4_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_local, paserk_local_len) == 0)
    {
        return format_paserk_key(paserk_local, paserk_local_len,
                                 key, paseto_v4_LOCAL_KEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_lid, paserk_lid_len) == 0)
    {
        char * paserk_key = paseto_v4_local_key_to_paserk(key, paserk_local, NULL, 0, NULL);
        size_t to_encode_len = paserk_lid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_lid, paserk_lid_len);
        memcpy(to_encode+paserk_lid_len, paserk_key, to_encode_len - paserk_lid_len);

        uint8_t hash[33];
        crypto_generichash(hash, sizeof(hash), to_encode, to_encode_len, NULL, 0);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_lid, paserk_lid_len,
                                 hash, sizeof(hash));
    }
    else if (strncmp(paserk_id, paserk_seal, paserk_seal_len) == 0)
    {
        size_t encoded_len = 0;
        uint8_t * encoded = paserk_v2_seal(&encoded_len,
            paserk_seal, paserk_seal_len,
            secret, secret_len,
            key, paseto_v4_LOCAL_KEYBYTES);

        char * output = format_paserk_key(paserk_seal, paserk_seal_len,
                                          encoded, encoded_len);
        free(encoded);
        return output;
    }
    else if (strncmp(paserk_id, paserk_local_wrap, paserk_local_wrap_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_wrap(
                    &out_len,
                    paserk_local_wrap, paserk_local_wrap_len,
                    secret, secret_len,
                    key, paseto_v4_LOCAL_KEYBYTES);
        char * output = format_paserk_key(paserk_local_wrap, paserk_local_wrap_len,
                                out, out_len);
        free(out);
        return output;
    }
    else if (strncmp(paserk_id, paserk_local_pw, paserk_local_pw_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_password_wrap(
                    &out_len,
                    paserk_local_pw, paserk_local_pw_len,
                    secret, secret_len,
                    key, paseto_v4_LOCAL_KEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_local_pw, paserk_local_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v4_local_key_from_paserk(
    uint8_t key[paseto_v4_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_local, paserk_local_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v4_LOCAL_KEYBYTES,
                paserk_key + paserk_local_len, paserk_key_len - paserk_local_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            if (len != paseto_v4_LOCAL_KEYBYTES)
            {
                fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                    len, paseto_v4_LOCAL_KEYBYTES);
                sodium_memzero(key, paseto_v4_LOCAL_KEYBYTES);
                errno = EINVAL;
                return false;
            }
            return true;
        }
        sodium_memzero(key, paseto_v4_LOCAL_KEYBYTES);
    }
    else if (strncmp(paserk_key, paserk_seal, paserk_seal_len) == 0)
    {
        // decode the base64 data
        size_t paserk_data_len = BASE64_TO_BIN_MAXLEN(paserk_key_len);
        uint8_t * paserk_data = (uint8_t *) malloc(paserk_data_len);
        if (!paserk_data) {
            errno = ENOMEM;
            return false;
        }
        size_t len;
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_seal_len, paserk_key_len - paserk_seal_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            errno = EINVAL;
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_unseal(&output_len,
                        paserk_seal, paserk_seal_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            errno = EINVAL;
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v4_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                output_len, paseto_v4_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v4_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    else if (strncmp(paserk_key, paserk_local_wrap, paserk_local_wrap_len) == 0)
    {
        // decode the base64 data
        size_t paserk_data_len = BASE64_TO_BIN_MAXLEN(paserk_key_len);
        uint8_t * paserk_data = (uint8_t *) malloc(paserk_data_len);
        if (!paserk_data) {
            errno = ENOMEM;
            return false;
        }
        size_t len;
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_local_wrap_len, paserk_key_len - paserk_local_wrap_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_unwrap(
                        &output_len,
                        paserk_local_wrap, paserk_local_wrap_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v4_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                output_len, paseto_v4_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v4_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    else if (strncmp(paserk_key, paserk_local_pw, paserk_local_pw_len) == 0)
    {
        // decode the base64 data
        size_t paserk_data_len = BASE64_TO_BIN_MAXLEN(paserk_key_len);
        uint8_t * paserk_data = (uint8_t *) malloc(paserk_data_len);
        if (!paserk_data) {
            errno = ENOMEM;
            return false;
        }
        size_t len;
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_local_pw_len, paserk_key_len - paserk_local_pw_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_password_unwrap(
                        &output_len,
                        paserk_local_pw, paserk_local_pw_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v4_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unwrapped key length mismatch: actual:%zu expected:%u\n",
                output_len, paseto_v4_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v4_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    errno = EINVAL;
    return false;
}
