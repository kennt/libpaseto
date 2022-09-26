extern "C" {
#include "paseto.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>
};

#include "cryptopp/cryptlib.h"
#include "cryptopp/modes.h"
using CryptoPP::CTR_Mode;

#include "cryptopp/hkdf.h"
using CryptoPP::HKDF;

#include "cryptopp/sha.h"
using CryptoPP::SHA384;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

static const uint8_t header[] = "v3.local.";
static const size_t header_len = sizeof(header) - 1;
static const size_t mac_len = HMAC<SHA384>::DIGESTSIZE;

static const uint8_t info_enc[] = "paseto-encryption-key";
static const size_t info_enc_len = sizeof(info_enc) - 1;
static const uint8_t info_auth[] = "paseto-auth-key-for-aead";
static const size_t info_auth_len = sizeof(info_auth) - 1;


bool paseto_v3_local_load_key_hex(
        uint8_t key[paseto_v3_LOCAL_KEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v3_LOCAL_KEYBYTES, key_hex);
}


bool paseto_v3_local_load_key_base64(
        uint8_t key[paseto_v3_LOCAL_KEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v3_LOCAL_KEYBYTES, key_base64);
}


void default_v3_generate_nonce(
        uint8_t nonce[paseto_v3_LOCAL_NONCEBYTES]) {
    randombytes_buf(nonce, paseto_v3_LOCAL_NONCEBYTES);
}


void dumpHex(const char *title, const uint8_t* p, size_t len)
{
    std::string result;
    HexEncoder encoder(new StringSink(result));
    encoder.Put(p, len);
    encoder.MessageEnd();
    std::cout << title << result << std::endl;
}

char *paseto_v3_local_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v3_LOCAL_KEYBYTES],
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
    if (nonce_in_len && nonce_in_len != paseto_v3_LOCAL_NONCEBYTES)
    {
        errno = EINVAL;
        return NULL;
    }

    const size_t to_encode_len = paseto_v3_LOCAL_NONCEBYTES + message_len + mac_len;
    uint8_t *to_encode = (uint8_t *) malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }

    /* #1. Check for local key */
    /* #2. Set header to "v3.local." */
    /* #3. Generate 32 bytes for the nonce */
    uint8_t * nonce = to_encode;
    size_t nonce_len = paseto_v3_LOCAL_NONCEBYTES;
    {
        if (nonce_in)
            memcpy(nonce, nonce_in, paseto_v3_LOCAL_NONCEBYTES);
        else
            default_v3_generate_nonce(nonce);
        nonce_len = paseto_v3_LOCAL_NONCEBYTES;
    }

    /* #4. Split the key into Ek and Ak with HKDF-HMAC-SHA384 */
    uint8_t enc_key[32];
    uint8_t counter_nonce[16];
    uint8_t auth_key[48];

    {
        HKDF<SHA384> hkdf;

        // build "paseto-encryption-key" + nonce
        uint8_t nonce_info_enc[paseto_v3_LOCAL_NONCEBYTES + info_enc_len];
        memcpy(nonce_info_enc, info_enc, info_enc_len);
        memcpy(nonce_info_enc+info_enc_len, nonce, nonce_len);

        uint8_t derived[48];
        hkdf.DeriveKey(derived, sizeof(derived), key, paseto_v3_LOCAL_KEYBYTES,
            NULL, 0, nonce_info_enc, sizeof(nonce_info_enc));

        memcpy(enc_key, derived, sizeof(enc_key));
        memcpy(counter_nonce, derived+sizeof(enc_key), sizeof(counter_nonce));

        // build "paseto-auth-key-for-aead" + nonce
        uint8_t nonce_info_auth[paseto_v3_LOCAL_NONCEBYTES + info_auth_len];
        memcpy(nonce_info_auth, info_auth, info_auth_len);
        memcpy(nonce_info_auth+info_auth_len, nonce, nonce_len);

        hkdf.DeriveKey(auth_key, sizeof(auth_key), key, paseto_v3_LOCAL_KEYBYTES,
            NULL, 0, nonce_info_auth, sizeof(nonce_info_auth));
    }
    
    /* #5. Encrypt message using AES-256-CTR */
    uint8_t * ciphertext;
    size_t ciphertext_len;

    {
        CTR_Mode< AES >::Encryption encryption;
        encryption.SetKeyWithIV(enc_key, sizeof(enc_key), counter_nonce);
        StreamTransformationFilter encryptor(encryption, NULL);
        encryptor.Put(message, message_len);
        encryptor.MessageEnd();

        ciphertext_len = encryptor.MaxRetrievable();
        if (ciphertext_len != message_len)
        {
            fprintf(stderr, "ciphertext length is not the same as plaintext length");
            free(to_encode);
            errno = EINVAL;
            return NULL;
        }
        ciphertext = (uint8_t *) to_encode + nonce_len;
        encryptor.Get(ciphertext, ciphertext_len);
    }

    /* #6. Pack h,n,c,f, and i using PAE */
    struct pre_auth pa;
    size_t pre_auth_len;

    {
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
        pre_auth_len = pa.current - pa.base;
    }

    /* #7. Calculate HMAC-SHA384 on pre_auth */
    {
        uint8_t *digest = ciphertext + ciphertext_len;
        HMAC<SHA384> hmac(auth_key, sizeof(auth_key));
        hmac.Update(pa.base, pre_auth_len);
        hmac.Final(digest);
    }

    free(pa.base);

    /* #8. Build the output */
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

uint8_t *paseto_v3_local_decrypt(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v3_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len)
{
    if (footer) *footer = NULL;
    if (footer_len) *footer_len = 0;

    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    /* #1. Check key */
    /* #2. Optionally check the footer */
    /* #3. Verify the header */
    {
        size_t minimum_len = header_len
                + sodium_base64_ENCODED_LEN(
                    paseto_v3_LOCAL_NONCEBYTES + mac_len,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1;
        if (strlen(encoded) < minimum_len)
        {
            errno = EINVAL;
            return NULL;
        }

        if (memcmp(encoded, header, header_len) != 0)
        {
            errno = EINVAL;
            return NULL;
        }
        encoded += header_len;
    }

    /* #4. Decode the payload */
    const size_t encoded_len = strlen(encoded);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;
    uint8_t * decoded;

    uint8_t *nonce;
    size_t nonce_len;
    uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t *digest;

    {
        uint8_t *body = NULL;
        size_t body_len = 0;

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
        nonce_len = paseto_v3_LOCAL_NONCEBYTES;
    
        ciphertext = body + nonce_len;
        ciphertext_len = body_len - nonce_len - mac_len;

        digest = body + nonce_len + ciphertext_len;
    }

    /* #5. Split the key using HKDF */
    uint8_t enc_key[32];
    uint8_t counter_nonce[16];
    uint8_t auth_key[48];
    
    {
        HKDF<SHA384> hkdf;
    
        // build "paseto-encryption-key" + nonce
        uint8_t nonce_info_enc[paseto_v3_LOCAL_NONCEBYTES + info_enc_len];
        memcpy(nonce_info_enc, info_enc, info_enc_len);
        memcpy(nonce_info_enc+info_enc_len, nonce, nonce_len);

        uint8_t derived[48];
        hkdf.DeriveKey(derived, sizeof(derived), key, paseto_v3_LOCAL_KEYBYTES,
            NULL, 0, nonce_info_enc, sizeof(nonce_info_enc));

        memcpy(enc_key, derived, sizeof(enc_key));
        memcpy(counter_nonce, derived+sizeof(enc_key), sizeof(counter_nonce));

        // build "paseto-auth-key-for-aead" + nonce
        uint8_t nonce_info_auth[paseto_v3_LOCAL_NONCEBYTES + info_auth_len];
        memcpy(nonce_info_auth, info_auth, info_auth_len);
        memcpy(nonce_info_auth+info_auth_len, nonce, nonce_len);

        hkdf.DeriveKey(auth_key, sizeof(auth_key), key, paseto_v3_LOCAL_KEYBYTES,
            NULL, 0, nonce_info_auth, sizeof(nonce_info_auth));
    }

    /* #6. Pack h,n,c,f, and i using PAE */
    struct pre_auth pa;
    size_t pre_auth_len = pa.current - pa.base;

    {
        if (!pre_auth_init(&pa, 5,
                header_len +
                nonce_len +
                ciphertext_len +
                decoded_footer_len +
                implicit_assertion_len))
        {
            free(decoded_footer);
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, nonce, paseto_v3_LOCAL_NONCEBYTES);
        pre_auth_append(&pa, ciphertext, ciphertext_len);
        pre_auth_append(&pa, decoded_footer, decoded_footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    /* #7. Recalculate HMAC of pa_auth */
    {
        uint8_t digest2[mac_len];
        HMAC<SHA384> hmac(auth_key, sizeof(auth_key));
        hmac.Update(pa.base, pre_auth_len);
        hmac.Final(digest2);

        free(pa.base);

        if (sodium_memcmp(digest, digest2, mac_len) != 0)
        {
            std::cerr << "digest failed " << __LINE__ << std::endl;
            free(decoded_footer);
            free(decoded);
            return NULL;
        }
    }

    /* #9. Decrypt message using AES-256-CTR */
    uint8_t * plaintext;
    size_t plaintext_len;

    {
        CTR_Mode< AES >::Decryption decryption;
        decryption.SetKeyWithIV(enc_key, sizeof(enc_key), counter_nonce);
        StreamTransformationFilter decryptor(decryption, NULL);
        decryptor.Put(ciphertext, ciphertext_len);
        decryptor.MessageEnd();

        plaintext_len = decryptor.MaxRetrievable();
        if (plaintext_len != ciphertext_len)
        {
            fprintf(stderr, "ciphertext length is not the same as plaintext length");
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
        plaintext = (uint8_t *) malloc(plaintext_len+1);
        if (plaintext == NULL)
        {
            free(decoded_footer);
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        decryptor.Get(plaintext, plaintext_len);

        // include a null terminator for convenience
        plaintext[plaintext_len] = '\0';
    }

    if (footer)
        *footer = decoded_footer;
    else
        free(decoded_footer);

    if (footer_len)
        *footer_len = decoded_footer_len;

    free(decoded);

    *message_len = plaintext_len;

    return plaintext;
}
