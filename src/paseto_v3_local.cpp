extern "C" {
#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>
};

#include "cryptopp/cryptlib.h"

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;
using CryptoPP::ECDSA_RFC6979;

#include "cryptopp/algebra.h"
using CryptoPP::Integer;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;

#include "cryptopp/hkdf.h"
using CryptoPP::HKDF;

#include "cryptopp/hmac.h"
using CryptoPP::HMAC;

#include "cryptopp/modes.h"
using CryptoPP::CTR_Mode;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/sha.h"
using CryptoPP::SHA384;

#include "helpers.hpp"


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

        sodium_memzero(derived, sizeof(derived));
        sodium_memzero(nonce_info_auth, sizeof(nonce_info_auth));
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
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(to_encode, to_encode_len);
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
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(to_encode, to_encode_len);
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

    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    /* #8. Build the output */
    char * output = encode_output(NULL,
                       header, header_len,
                       to_encode, to_encode_len,
                       footer, footer_len);
    if (output == NULL)
    {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(counter_nonce, sizeof(counter_nonce));
        sodium_memzero(auth_key, sizeof(auth_key));
        sodium_memzero(to_encode, to_encode_len);
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    sodium_memzero(to_encode, to_encode_len);
    free(to_encode);

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(counter_nonce, sizeof(counter_nonce));
    sodium_memzero(auth_key, sizeof(auth_key));
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
                + BIN_TO_BASE64_MAXLEN(paseto_v3_LOCAL_NONCEBYTES + mac_len) - 1;
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

        sodium_memzero(derived, sizeof(derived));
        sodium_memzero(nonce_info_auth, sizeof(nonce_info_auth));
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
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
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

        sodium_memzero(pa.base, pre_auth_len);
        free(pa.base);

        if (sodium_memcmp(digest, digest2, mac_len) != 0)
        {
            std::cerr << "digest failed " << __LINE__ << std::endl;
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(digest2, sizeof(digest2));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
        sodium_memzero(digest2, sizeof(digest2));
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
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
        plaintext = (uint8_t *) malloc(plaintext_len+1);
        if (plaintext == NULL)
        {
            sodium_memzero(enc_key, sizeof(enc_key));
            sodium_memzero(counter_nonce, sizeof(counter_nonce));
            sodium_memzero(auth_key, sizeof(auth_key));
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
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
    {
        sodium_memzero(decoded_footer, decoded_footer_len);
        free(decoded_footer);
    }

    if (footer_len)
        *footer_len = decoded_footer_len;

    sodium_memzero(decoded, body_len);
    free(decoded);

    *message_len = plaintext_len;

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(counter_nonce, sizeof(counter_nonce));
    sodium_memzero(auth_key, sizeof(auth_key));
    return plaintext;
}

static const char paserk_local[] = "k3.local.";
static const size_t paserk_local_len = sizeof(paserk_local) - 1;
static const char paserk_lid[] = "k3.lid.";
static const size_t paserk_lid_len = sizeof(paserk_lid) - 1;
static const char paserk_seal[] = "k3.seal.";
static const size_t paserk_seal_len = sizeof(paserk_seal) - 1;
static const char paserk_local_wrap[] = "k3.local-wrap.pie.";
static const size_t paserk_local_wrap_len = sizeof(paserk_local_wrap) - 1;
static const char paserk_local_pw[] = "k3.local-pw.";
static const size_t paserk_local_pw_len = sizeof(paserk_local_pw) - 1;


uint8_t * paserk_v3_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len)
{
    if (!wrapkey || !data)
    {
        errno = EINVAL;
        return NULL;
    }

    // #1. Enforce algorithm lucidity
    // #2. Generate a randam nonce
    uint8_t nonce[32];
    randombytes_buf(nonce, sizeof(nonce));

    // #3. Derive encryption key (Ek) and nonce2
    uint8_t Ek[32];
    uint8_t nonce2[16];
    {
        uint8_t digest[HMAC<SHA384>::DIGESTSIZE];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x80;
        memcpy(to_hash+1, nonce, sizeof(nonce));

        HMAC<SHA384> hmac(wrapkey, wrapkey_len);
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(digest);

        memcpy(Ek, digest, sizeof(Ek));
        memcpy(nonce2, digest+sizeof(Ek), sizeof(nonce2));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #4. Derive authentication key (Ak)
    uint8_t Ak[32];
    {
        uint8_t digest[HMAC<SHA384>::DIGESTSIZE];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x81;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        HMAC<SHA384> hmac(wrapkey, wrapkey_len);
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(digest);

        memcpy(Ak, digest, sizeof(Ak));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #5. Encrypt plaintext key (data) as ciphertext
    size_t ciphertext_len = data_len;
    uint8_t * ciphertext = (uint8_t *) malloc(ciphertext_len);
    if (!ciphertext)
    {
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(nonce2, sizeof(nonce2));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        errno = ENOMEM;
        return NULL;
    }

    {
        CTR_Mode< AES >::Encryption encryption;
        encryption.SetKeyWithIV(Ek, sizeof(Ek), nonce2);
        StreamTransformationFilter encryptor(encryption, NULL);
        encryptor.Put(data, data_len);
        encryptor.MessageEnd();

        if (encryptor.MaxRetrievable() != data_len)
        {
            fprintf(stderr, "wrap: ciphertext length(%zu) is not the same as plaintext length (%zu)",
                encryptor.MaxRetrievable(), data_len);
            sodium_memzero(nonce, sizeof(nonce));
            sodium_memzero(nonce2, sizeof(nonce2));
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(ciphertext, ciphertext_len);
            free(ciphertext);
            errno = EINVAL;
            return NULL;
        }
        encryptor.Get(ciphertext, ciphertext_len);
    }

    // #6. Calculate authentication tag (tag)
    uint8_t tag[48];
    {
        uint8_t to_hash[header_len + sizeof(nonce) + ciphertext_len];
        memcpy(to_hash, header, header_len);
        memcpy(to_hash + header_len, nonce, sizeof(nonce));
        memcpy(to_hash + header_len + sizeof(nonce), ciphertext, ciphertext_len);
        HMAC<SHA384> hmac(Ak, sizeof(Ak));
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(tag);

        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #7. Return tag || nonce || ciphertext
    size_t out_len = sizeof(tag) + sizeof(nonce) + ciphertext_len;
    uint8_t * out = (uint8_t *) malloc(out_len);
    if (!out) {
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(nonce2, sizeof(nonce2));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag, sizeof(tag));
        sodium_memzero(ciphertext, ciphertext_len);
        free(ciphertext);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(out, tag, sizeof(tag));
    memcpy(out + sizeof(tag), nonce, sizeof(nonce));
    memcpy(out + sizeof(tag) + sizeof(nonce), ciphertext, ciphertext_len);

    sodium_memzero(ciphertext, ciphertext_len);
    free(ciphertext);

    if (output_len)
        *output_len = out_len;

    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(nonce2, sizeof(nonce2));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(tag, sizeof(tag));
    return out;
}

uint8_t * paserk_v3_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len)
{
    if (!wrapkey || !data)
    {
        errno = EINVAL;
        return NULL;
    }

    // #1. Decode base64, break apart into tag, nonce, and cipherkey
    uint8_t tag[48];
    uint8_t nonce[32];

    if (data_len <= (sizeof(tag) + sizeof(nonce)))
    {
        fprintf(stderr, "encrypted data too short: actual:%zu <= expected:%zu\n",
            data_len,  sizeof(tag) + sizeof(nonce));
        errno = EINVAL;
        return NULL;
    }

    size_t ciphertext_len = data_len - sizeof(tag) - sizeof(nonce);
    uint8_t * ciphertext = (uint8_t *) malloc(ciphertext_len);
    if (!ciphertext) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(tag, data, sizeof(tag));
    memcpy(nonce, data+sizeof(tag), sizeof(nonce));
    memcpy(ciphertext, data + sizeof(tag) + sizeof(nonce), ciphertext_len);

    // #2. Derive auth key
    uint8_t Ak[32];
    {
        uint8_t digest[HMAC<SHA384>::DIGESTSIZE];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x81;
        memcpy(to_hash+1, nonce, sizeof(nonce));

        HMAC<SHA384> hmac(wrapkey, wrapkey_len);
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(digest);

        memcpy(Ak, digest, sizeof(Ak));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));;
    }

    // #3. Recalculate auth tag
    uint8_t tag2[HMAC<SHA384>::DIGESTSIZE];
    {
        uint8_t to_hash[header_len + sizeof(nonce) + ciphertext_len];
        memcpy(to_hash, header, header_len);
        memcpy(to_hash + header_len, nonce, sizeof(nonce));
        memcpy(to_hash + header_len + sizeof(nonce), ciphertext, ciphertext_len);

        HMAC<SHA384> hmac(Ak, sizeof(Ak));
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(tag2);

        sodium_memzero(to_hash, sizeof(to_hash));;
    }

    // #4. Compare tags
    if (sodium_memcmp(tag, tag2, sizeof(tag)) != 0)
    {
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag2, sizeof(tag2));
        sodium_memzero(tag, sizeof(tag));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(ciphertext, ciphertext_len);
        free(ciphertext);
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(tag2, sizeof(tag2));

    // #5. Derive encryption key and nonce3
    uint8_t Ek[32];
    uint8_t nonce2[16];
    {
        uint8_t digest[HMAC<SHA384>::DIGESTSIZE];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x80;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        HMAC<SHA384> hmac(wrapkey, wrapkey_len);
        hmac.Update(to_hash, sizeof(to_hash));
        hmac.Final(digest);

        memcpy(Ek, digest, sizeof(Ek));
        memcpy(nonce2, digest+sizeof(Ek), sizeof(nonce2));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));;
    }

    // #6. Decrypt cipherkey
    size_t plaintext_len;
    uint8_t * plaintext;
    {
        CTR_Mode< AES >::Decryption decryption;
        decryption.SetKeyWithIV(Ek, sizeof(Ek), nonce2);
        StreamTransformationFilter decryptor(decryption, NULL);
        decryptor.Put(ciphertext, ciphertext_len);
        decryptor.MessageEnd();

        plaintext_len = decryptor.MaxRetrievable();
        if (plaintext_len != ciphertext_len)
        {
            fprintf(stderr, "ciphertext length is not the same as plaintext length");
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(nonce2, sizeof(nonce2));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(tag, sizeof(tag));
            sodium_memzero(nonce, sizeof(nonce));
            sodium_memzero(ciphertext, ciphertext_len);
            free(ciphertext);
            errno = EINVAL;
            return NULL;
        }
        plaintext = (uint8_t *) malloc(plaintext_len+1);
        if (plaintext == NULL)
        {
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(nonce2, sizeof(nonce2));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(tag, sizeof(tag));
            sodium_memzero(nonce, sizeof(nonce));
            sodium_memzero(ciphertext, ciphertext_len);
            free(ciphertext);
            errno = ENOMEM;
            return NULL;
        }
        decryptor.Get(plaintext, plaintext_len);

        // include a null terminator for convenience
        plaintext[plaintext_len] = '\0';
    }

    sodium_memzero(ciphertext, ciphertext_len);
    free(ciphertext);

    // #7. Algorithm lucidity
    // #8. Return plaintext
    if (output_len)
        *output_len = plaintext_len;

    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(nonce2, sizeof(nonce2));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(tag, sizeof(tag));
    sodium_memzero(nonce, sizeof(nonce));
    return plaintext;
}


uint8_t * paserk_v3_password_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len,
    v3PasswordParams *params)
{
    if (!password || !data || !params) {
        errno = EINVAL;
        return NULL;
    }
    uint32_t iterations = params->iterations;

    // #1. Generate a random 32-byte salt (s)
    uint8_t salt[32];
    randombytes_buf(salt, sizeof(salt));

    // #2. Derive pre-key k from the password and salt (k)
    uint8_t prekey[32];
    {
        PKCS5_PBKDF2_HMAC<SHA384> pbkdf;
        pbkdf.DeriveKey(prekey, sizeof(prekey),
            0, password, password_len, salt, sizeof(salt),
            iterations, 0);
    }

    // #3. Derive encryption key (Ek)
    // #4. Derive the authentication key (Ak)
    uint8_t Ek[32];
    uint8_t Ak[48];
    {
        uint8_t digest[48];

        uint8_t to_hash[1 + sizeof(prekey)];
        to_hash[0] = 0xFF;
        memcpy(to_hash + 1, prekey, sizeof(prekey));
        SHA384 sha;
        sha.CalculateDigest(digest, to_hash, sizeof(to_hash));
        memcpy(Ek, digest, sizeof(Ek));

        to_hash[0] = 0xFE;
        sha.Restart();
        sha.CalculateDigest(digest, to_hash, sizeof(to_hash));
        memcpy(Ak, digest, sizeof(Ak));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #5. Generate random 16-byte nonce (n)
    uint8_t nonce[16];
    randombytes_buf(nonce, sizeof(nonce));

    // #6. Encrypt plaintext key (ptk) to get encrypted data key (edk)
    size_t edk_len = data_len;
    uint8_t * edk;
    {
        CTR_Mode< AES >::Encryption encryption;
        encryption.SetKeyWithIV(Ek, sizeof(Ek), nonce);
        StreamTransformationFilter encryptor(encryption, NULL);
        encryptor.Put(data, data_len);
        encryptor.MessageEnd();

        if (encryptor.MaxRetrievable() != data_len)
        {
            fprintf(stderr, "ciphertext length is not the same as plaintext length");
            sodium_memzero(salt, sizeof(salt));
            sodium_memzero(prekey, sizeof(prekey));
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(nonce, sizeof(nonce));
            errno = EINVAL;
            return NULL;
        }
        edk = (uint8_t *) malloc(edk_len);
        if (!edk) {
            sodium_memzero(salt, sizeof(salt));
            sodium_memzero(prekey, sizeof(prekey));
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(nonce, sizeof(nonce));
            errno = ENOMEM;
            return NULL;
        }
        encryptor.Get(edk, edk_len);
    }

    // #7. Calculate the authentication tag (tag)
    size_t buffer_len = header_len
                        + sizeof(salt)
                        + sizeof(uint32_t)      // iterations
                        + sizeof(nonce)
                        + edk_len
                        + 48;                   // sizeof(tag)
    uint8_t * buffer = (uint8_t *) malloc(buffer_len);
    if (!buffer) {
        sodium_memzero(salt, sizeof(salt));
        sodium_memzero(prekey, sizeof(prekey));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(edk, edk_len);
        free(edk);
        errno = ENOMEM;
        return NULL;
    }
    {
        uint8_t * current = buffer;
        memcpy(current, header, header_len);
        current += header_len;

        memcpy(current, salt, sizeof(salt));
        current += sizeof(salt);

        current = WRITE32BE(current, iterations);

        memcpy(current, nonce, sizeof(nonce));
        current += sizeof(nonce);

        memcpy(current, edk, edk_len);
        current += edk_len;

        // This will place the tag at the end of the
        // buffer, so that it's ready for output
        HMAC<SHA384> hmac(Ak, sizeof(Ak));
        hmac.Update(buffer, current - buffer);
        hmac.Final(current);
    }
    sodium_memzero(edk, edk_len);
    free(edk);

    // #8. Return the result
    // Now move the buffer down (we do not want to return the header)
    memmove(buffer, buffer + header_len, buffer_len - header_len);

    if (output_len)
        *output_len = buffer_len - header_len;

    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(prekey, sizeof(prekey));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(nonce, sizeof(nonce));
    return buffer;
}


uint8_t * paserk_v3_password_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len)
{
    if (!password || !data)
    {
        errno = EINVAL;
        return NULL;
    }

    size_t salt_len = 32;
    size_t nonce_len = 16;
    size_t tag_len = 48;
    size_t edk_len = data_len
                        - salt_len
                        - sizeof(uint32_t)
                        - nonce_len
                        - tag_len;

    if (data_len <= (salt_len + sizeof(uint32_t) + nonce_len + tag_len))
    {
        fprintf(stderr, "encrypted data too short: actual:%zu <= expected:%zu\n",
            data_len,  salt_len + sizeof(uint32_t) + nonce_len + tag_len);
        errno = EINVAL;
        return NULL;
    }

    const uint8_t * salt;
    uint32_t iterations;
    const uint8_t * nonce;
    const uint8_t * edk;
    const uint8_t * tag;

    const uint8_t * current = data;
    salt = current;
    current += salt_len;

    iterations = READ32BE(current);
    current += sizeof(uint32_t);

    nonce = current;
    current += nonce_len;

    edk = current;
    current += edk_len;

    tag = current;

    // #1. Algorithm lucidity
    // #2. Derive pre-key
    uint8_t prekey[32];
    {
        PKCS5_PBKDF2_HMAC<SHA384> pbkdf;
        pbkdf.DeriveKey(prekey, sizeof(prekey),
            0, password, password_len, salt, salt_len,
            iterations, 0);
    }

    // #3. Derive the authentication key (Ak)
    uint8_t Ak[48];
    {
        uint8_t digest[48];
        uint8_t to_hash[sizeof(prekey) + 1];
        to_hash[0] = 0xFE;
        memcpy(to_hash + 1, prekey, sizeof(prekey));

        SHA384 sha;
        sha.CalculateDigest(digest, to_hash, sizeof(to_hash));

        memcpy(Ak, digest, sizeof(Ak));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #4. Recalculate the auth tag
    uint8_t tag2[48];
    {
        size_t to_hash_len = header_len + salt_len + sizeof(uint32_t)
                                + nonce_len + edk_len;
        uint8_t * to_hash = (uint8_t *) malloc(to_hash_len);
        if (!to_hash) {
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(prekey, sizeof(prekey));
            errno = ENOMEM;
            return NULL;
        }
        uint8_t * current = to_hash;

        memcpy(current, header, header_len);
        current += header_len;
        memcpy(current, salt, salt_len);
        current += salt_len;
        current = WRITE32BE(current, iterations);
        memcpy(current, nonce, nonce_len);
        current += nonce_len;
        memcpy(current, edk, edk_len);

        HMAC<SHA384> hmac(Ak, sizeof(Ak));
        hmac.Update(to_hash, to_hash_len);
        hmac.Final(tag2);

        sodium_memzero(to_hash, to_hash_len);
        free(to_hash);
    }

    // #5. Compare tags
    if (sodium_memcmp(tag, tag2, sizeof(tag2)) != 0)
    {
        sodium_memzero(tag2, sizeof(tag2));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(prekey, sizeof(prekey));
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(tag2, sizeof(tag2));

    // #6. Derive encryption key
    uint8_t Ek[32];
    {
        uint8_t digest[HMAC<SHA384>::DIGESTSIZE];
        uint8_t to_hash[1 + sizeof(prekey)];
        to_hash[0] = 0xFF;
        memcpy(to_hash+1, prekey, sizeof(prekey));

        SHA384 sha;
        sha.CalculateDigest(digest, to_hash, sizeof(to_hash));

        memcpy(Ek, digest, sizeof(Ek));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #7. Decrypt encrypted key (edk)
    size_t plaintext_len = edk_len;
    uint8_t * plaintext;
    {
        CTR_Mode< AES >::Decryption decryption;
        decryption.SetKeyWithIV(Ek, sizeof(Ek), nonce);
        StreamTransformationFilter decryptor(decryption, NULL);
        decryptor.Put(edk, edk_len);
        decryptor.MessageEnd();

        plaintext_len = decryptor.MaxRetrievable();
        if (plaintext_len != edk_len)
        {
            fprintf(stderr, "ciphertext length is not the same as plaintext length");
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(prekey, sizeof(prekey));
            errno = EINVAL;
            return NULL;
        }
        plaintext = (uint8_t *) malloc(plaintext_len+1);
        if (plaintext == NULL)
        {
            sodium_memzero(Ek, sizeof(Ek));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(prekey, sizeof(prekey));
            errno = ENOMEM;
            return NULL;
        }
        decryptor.Get(plaintext, plaintext_len);

        // include a null terminator for convenience
        plaintext[plaintext_len] = '\0';
    }

    // #8. Return plaintext
    if (output_len)
        *output_len = plaintext_len;

    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(prekey, sizeof(prekey));
    return plaintext;
}


char * paseto_v3_local_key_to_paserk(
    uint8_t key[paseto_v3_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_local, paserk_local_len) == 0)
    {
        return format_paserk_key(paserk_local, paserk_local_len,
                                 key, paseto_v3_LOCAL_KEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_lid, paserk_lid_len) == 0)
    {
        char * paserk_key = paseto_v3_local_key_to_paserk(key, paserk_local, NULL, 0, NULL);
        size_t to_encode_len = paserk_lid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_lid, paserk_lid_len);
        memcpy(to_encode+paserk_lid_len, paserk_key, to_encode_len - paserk_lid_len);

        uint8_t digest[48];
        SHA384 sha;
        sha.CalculateDigest(digest, to_encode, to_encode_len);

        // assert that sha.DigestSize() > 33
        uint8_t hash[33];
        memcpy(hash, digest, 33);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_lid, paserk_lid_len,
                                 hash, sizeof(hash));
    }
    else if (strncmp(paserk_id, paserk_seal, paserk_seal_len) == 0)
    {
        uint8_t pk[P384_COMPRESSED_PUBLICKEYBYTES];

        if (secret_len != P384_COMPRESSED_PUBLICKEYBYTES)
        {
            fprintf(stderr, "Unexpected public key length: actual:%zu expected:%d\n"
                            "A compressed P-384 public key is expected.\n",
                secret_len,
                P384_COMPRESSED_PUBLICKEYBYTES);
            errno = EINVAL;
            return NULL;
        }
        memcpy(pk, secret, secret_len);

        // #1. Generate random ephemeral P-384 keypair (esk, epk)
        uint8_t esk[P384_SECRETKEYBYTES];
        uint8_t epk[P384_COMPRESSED_PUBLICKEYBYTES];
        {
            AutoSeededRandomPool rng;
            ECDH<ECP>::Domain ecdh(CryptoPP::ASN1::secp384r1());

            SecByteBlock priv(ecdh.PrivateKeyLength());
            SecByteBlock pub(ecdh.PublicKeyLength());

            // Public/private key lengths are 48-bytes (due to 384-bit algorithm)
            if (ecdh.PrivateKeyLength() != P384_SECRETKEYBYTES)
            {
                fprintf(stderr, "Unexpected private key length: actual:%u expected:%d\n",
                    ecdh.PrivateKeyLength(), P384_SECRETKEYBYTES);
                sodium_memzero(pk, sizeof(pk));
                errno = EINVAL;
                return NULL;
            }
            // The public key is a combination of privatekey + publickey + header-byte
            if (ecdh.PublicKeyLength() != (P384_SECRETKEYBYTES + P384_COMPRESSED_PUBLICKEYBYTES))
            {
                fprintf(stderr, "Unexpected ECDH public key length: actual:%u expected:%d\n",
                    ecdh.PublicKeyLength(),
                    (P384_SECRETKEYBYTES + P384_COMPRESSED_PUBLICKEYBYTES));
                sodium_memzero(pk, sizeof(pk));
                errno = EINVAL;
                return NULL;
            }

            // priv is the private key exponent (which is what we want)
            ecdh.GenerateKeyPair(rng, priv, pub);
            memcpy(esk, priv.BytePtr(), priv.SizeInBytes());

            // pub is the x,y coords (should start with 04)
            Integer y(pub.BytePtr() + P384_COMPRESSED_PUBLICKEYBYTES, P384_PUBLICKEYBYTES);
            epk[0] = (y.GetBit(0) ? 0x03 : 0x02);
            memcpy(epk + 1, pub.BytePtr() + 1, P384_PUBLICKEYBYTES);
        }

        // #2. Calculate shared secret xk
        uint8_t xk[48];

        {
            ECDH<ECP>::Domain dh( CryptoPP::ASN1::secp384r1() );
            dh.AccessGroupParameters().SetPointCompression(true);

            SecByteBlock privkey(esk, sizeof(esk));
            SecByteBlock pubkey(pk, sizeof(pk));

            SecByteBlock shared(dh.AgreedValueLength());
            if (!dh.Agree(shared, privkey, pubkey))
            {
                fprintf(stderr, "could not determine ECDH shared secret\n");
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(esk, sizeof(esk));
                sodium_memzero(epk, sizeof(epk));
                errno = EINVAL;
                return NULL;
            }
            if (shared.SizeInBytes() != sizeof(xk))
            {
                fprintf(stderr, "ECDH shared key size not as expected: actual:%zu  expected:%zu",
                    shared.SizeInBytes(), sizeof(xk));
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(esk, sizeof(esk));
                sodium_memzero(epk, sizeof(epk));
                errno = EINVAL;
                return NULL;
            }
            memcpy(xk, shared.BytePtr(), sizeof(xk));
        }

        // #3. Calculate encryption key Ek and nonce
        // #4. Calculate the auth key (Ak)
        uint8_t Ek[32];
        uint8_t nonce[16];
        uint8_t Ak[48];

        {
            uint8_t buffer[1 + paserk_seal_len + sizeof(xk) + sizeof(epk) + sizeof(pk)];
            buffer[0] = 0x01;
            memcpy(buffer + 1, paserk_seal, paserk_seal_len);
            memcpy(buffer + 1 + paserk_seal_len, xk, sizeof(xk));
            memcpy(buffer + 1 + paserk_seal_len + sizeof(xk), epk, sizeof(epk));
            memcpy(buffer + 1 + paserk_seal_len + sizeof(xk) + sizeof(epk), pk, sizeof(pk));

            uint8_t digest[48];
            SHA384 sha;
            sha.CalculateDigest(digest, buffer, sizeof(buffer));

            memcpy(Ek, digest, sizeof(Ek));
            memcpy(nonce, digest + sizeof(Ek), sizeof(nonce));

            buffer[0] = 0x02;
            sha.Restart();
            sha.CalculateDigest(Ak, buffer, sizeof(buffer));

            sodium_memzero(buffer, sizeof(buffer));
            sodium_memzero(digest, sizeof(digest));
        }

        // #5. Encrypt plaintext datakey (pdk)
        uint8_t edk[paseto_v3_LOCAL_KEYBYTES];

        {
            CTR_Mode< AES >::Encryption encryption;
            encryption.SetKeyWithIV(Ek, sizeof(Ek), nonce);
            StreamTransformationFilter encryptor(encryption, NULL);
            encryptor.Put(key, paseto_v3_LOCAL_KEYBYTES);
            encryptor.MessageEnd();

            if (encryptor.MaxRetrievable() != paseto_v3_LOCAL_KEYBYTES)
            {
                fprintf(stderr, "ciphertext length is not the same as plaintext length");
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(esk, sizeof(esk));
                sodium_memzero(epk, sizeof(epk));
                sodium_memzero(xk, sizeof(xk));
                sodium_memzero(Ek, sizeof(Ek));
                sodium_memzero(nonce, sizeof(nonce));
                sodium_memzero(Ak, sizeof(Ak));
                errno = EINVAL;
                return NULL;
            }
            encryptor.Get(edk, sizeof(edk));
        }

        // #6. Calculate auth tag (tag)
        uint8_t tag[48];

        {
            uint8_t message[paserk_seal_len + sizeof(epk) + sizeof(edk)];
            memcpy(message, paserk_seal, paserk_seal_len);
            memcpy(message + paserk_seal_len, epk, sizeof(epk));
            memcpy(message + paserk_seal_len + sizeof(epk), edk, sizeof(edk));
            HMAC<SHA384> hmac(Ak, sizeof(Ak));
            hmac.Update(message, sizeof(message));
            hmac.Final(tag);

            sodium_memzero(message, sizeof(message));
        }

        // #7. Return h || base64(tag || epk || edk)
        uint8_t output[sizeof(tag) + sizeof(epk) + sizeof(edk)];
        memcpy(output, tag, sizeof(tag));
        memcpy(output + sizeof(tag), epk, sizeof(epk));
        memcpy(output + sizeof(tag) + sizeof(epk), edk, sizeof(edk));

        sodium_memzero(pk, sizeof(pk));
        sodium_memzero(esk, sizeof(esk));
        sodium_memzero(epk, sizeof(epk));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(edk, sizeof(edk));
        sodium_memzero(tag, sizeof(tag));
        char * result = format_paserk_key(paserk_seal, paserk_seal_len,
                                 output, sizeof(output));
        sodium_memzero(output, sizeof(output));
        return result;
    }
    else if (strncmp(paserk_id, paserk_local_wrap, paserk_local_wrap_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v3_wrap(
                &out_len,
                paserk_local_wrap, paserk_local_wrap_len,
                secret, secret_len,
                key, paseto_v3_LOCAL_KEYBYTES);
        if (!out) {
            errno = ENOMEM;
            return NULL;
        }
        char * result = format_paserk_key(paserk_local_wrap, paserk_local_wrap_len,
                                 out, out_len);
        paseto_free(out);
        return result;
    }
    else if (strncmp(paserk_id, paserk_local_pw, paserk_local_pw_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v3_password_wrap(
                    &out_len,
                    paserk_local_pw, paserk_local_pw_len,
                    secret, secret_len,
                    key, paseto_v3_LOCAL_KEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_local_pw, paserk_local_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}


bool paseto_v3_local_key_from_paserk(
    uint8_t key[paseto_v3_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_local, paserk_local_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v3_LOCAL_KEYBYTES,
                paserk_key + paserk_local_len, paserk_key_len - paserk_local_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            return true;
        }
    }
    else if (strncmp(paserk_key, paserk_seal, paserk_seal_len) == 0)
    {
        if (secret_len != P384_SECRETKEYBYTES)
        {
            fprintf(stderr, "Unexpected secret key length: actual:%zu expected:%d\n"
                            "A P-384 secret key is expected.\n",
                secret_len,
                P384_SECRETKEYBYTES);
            errno = EINVAL;
            return false;
        }

        // decode the base64 data
        size_t paserk_data_len = BASE64_TO_BIN_MAXLEN(paserk_key_len);
        uint8_t * paserk_data = (uint8_t *) malloc(paserk_data_len);
        if (!paserk_data) {
            errno = ENOMEM;
            return false;
        }
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_seal_len, paserk_key_len - paserk_seal_len,
                NULL, &paserk_data_len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            sodium_memzero(paserk_data, paserk_data_len);
            free(paserk_data);
            return false;
        }

        // #1. Verify header and sk
        // TODO: check the sk len
        const uint8_t * sk = secret;
        size_t tag_len = 48;
        size_t epk_len = P384_COMPRESSED_PUBLICKEYBYTES;

        if (paserk_data_len <= (tag_len + epk_len))
        {
            fprintf(stderr, "encrypted data too short: actual:%zu <= expected:%zu\n",
                paserk_data_len, tag_len + epk_len);
            sodium_memzero(paserk_data, paserk_data_len);
            free(paserk_data);
            errno = EINVAL;
            return false;
        }

        size_t edk_len = paserk_data_len - epk_len - tag_len;
        uint8_t * tag = paserk_data;
        uint8_t * epk = paserk_data + tag_len;
        uint8_t * edk = paserk_data + tag_len + epk_len;

        if (edk_len != paseto_v3_LOCAL_KEYBYTES)
        {
            sodium_memzero(paserk_data, paserk_data_len);
            free(paserk_data);
            errno = EINVAL;
            return false;
        }

        uint8_t pk[P384_COMPRESSED_PUBLICKEYBYTES];

        // Derive the pk from the sk
        {
            ECDSA_RFC6979<ECP,SHA384>::PrivateKey secret_key;
            ECDSA_RFC6979<ECP,SHA384>::PublicKey public_key;
            AutoSeededRandomPool prng;

            /* Initialize the sk */
            Integer x {sk, P384_SECRETKEYBYTES};
            secret_key.Initialize(CryptoPP::ASN1::secp384r1(), x);

            if (!secret_key.Validate(prng, 3))
            {
                fprintf(stderr, "secret key validate() failed (%d)\n", __LINE__);
                sodium_memzero(paserk_data, paserk_data_len);
                free(paserk_data);
                errno = EINVAL;
                return false;
            }

            /* get the pk from the sk */
            secret_key.MakePublicKey(public_key);

            /* save as point-compressed */
            std::string pubkey_hex;
            pubkey_hex = p384_publickey_to_hex(public_key);
            key_load_hex(pk, sizeof(pk), pubkey_hex.c_str());

            sodium_memzero(pubkey_hex.data(), pubkey_hex.length());
        }

        // #2. Calculate shared secret xk
        uint8_t xk[48];

        {
            ECDH<ECP>::Domain dh( CryptoPP::ASN1::secp384r1() );
            dh.AccessGroupParameters().SetPointCompression(true);

            SecByteBlock privkey(sk, secret_len);
            SecByteBlock pubkey(epk, epk_len);

            SecByteBlock shared(dh.AgreedValueLength());
            if (!dh.Agree(shared, privkey, pubkey))
            {
                fprintf(stderr, "could not determine ECDH shared secret\n");
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(paserk_data, paserk_data_len);
                free(paserk_data);
                errno = EINVAL;
                return false;
            }
            if (shared.SizeInBytes() != sizeof(xk))
            {
                fprintf(stderr, "ECDH shared key size not as expected: actual:%zu  expected:%zu",
                    shared.SizeInBytes(), sizeof(xk));
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(paserk_data, paserk_data_len);
                free(paserk_data);
                errno = EINVAL;
                return false;
            }
            memcpy(xk, shared.BytePtr(), sizeof(xk));
        }

        // #3. Calculate the authentication key (Ak)
        uint8_t Ak[48];
        uint8_t buffer[1 + paserk_seal_len + sizeof(xk) + epk_len + sizeof(pk)];

        {
            buffer[0] = 0x02;
            memcpy(buffer + 1, paserk_seal, paserk_seal_len);
            memcpy(buffer + 1 + paserk_seal_len, xk, sizeof(xk));
            memcpy(buffer + 1 + paserk_seal_len + sizeof(xk), epk, epk_len);
            memcpy(buffer + 1 + paserk_seal_len + sizeof(xk) + epk_len, pk, sizeof(pk));

            SHA384 sha;
            sha.CalculateDigest(Ak, buffer, sizeof(buffer));
        }

        // #4. Recalc the auth tag
        uint8_t tag2[48];
        {
            uint8_t message[paserk_seal_len + epk_len + edk_len];
            memcpy(message, paserk_seal, paserk_seal_len);
            memcpy(message + paserk_seal_len, epk, epk_len);
            memcpy(message + paserk_seal_len + epk_len, edk, edk_len);
            HMAC<SHA384> hmac(Ak, sizeof(Ak));
            hmac.Update(message, sizeof(message));
            hmac.Final(tag2);

            sodium_memzero(message, sizeof(message));
        }

        // #5. Compare tags
        if (sodium_memcmp(tag, tag2, sizeof(tag2)) != 0)
        {
            sodium_memzero(tag2, sizeof(tag2));
            sodium_memzero(buffer, sizeof(buffer));
            sodium_memzero(Ak, sizeof(Ak));
            sodium_memzero(xk, sizeof(xk));
            sodium_memzero(pk, sizeof(pk));
            sodium_memzero(paserk_data, paserk_data_len);
            free(paserk_data);
            errno = EINVAL;
            return false;
        }
        sodium_memzero(tag2, sizeof(tag2));

        // #6. Calculate the encryption key (Ek)
        uint8_t Ek[32];
        uint8_t nonce[16];
        {
            uint8_t digest[48];
            buffer[0] = 0x01;

            SHA384 sha;
            sha.CalculateDigest(digest, buffer, sizeof(buffer));

            memcpy(Ek, digest, sizeof(Ek));
            memcpy(nonce, digest + sizeof(Ek), sizeof(nonce));

            sodium_memzero(digest, sizeof(digest));
        }

        // #7. Decrypt
        uint8_t pdk[paseto_v3_LOCAL_KEYBYTES + 1];
        size_t pdk_len = sizeof(pdk) - 1;
        {
            CTR_Mode< AES >::Decryption decryption;
            decryption.SetKeyWithIV(Ek, sizeof(Ek), nonce);
            StreamTransformationFilter decryptor(decryption, NULL);
            decryptor.Put(edk, edk_len);
            decryptor.MessageEnd();

            size_t plaintext_len = decryptor.MaxRetrievable();
            if (plaintext_len != paseto_v3_LOCAL_KEYBYTES)
            {
                fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                    plaintext_len, paseto_v3_LOCAL_KEYBYTES);
                sodium_memzero(Ek, sizeof(Ek));
                sodium_memzero(nonce, sizeof(nonce));
                sodium_memzero(buffer, sizeof(buffer));
                sodium_memzero(Ak, sizeof(Ak));
                sodium_memzero(xk, sizeof(xk));
                sodium_memzero(pk, sizeof(pk));
                sodium_memzero(paserk_data, paserk_data_len);
                free(paserk_data);
                errno = EINVAL;
                return false;
            }
            decryptor.Get(pdk, pdk_len);
            pdk[pdk_len] = '\0';
        }

        // #8. Return the plaintext
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(buffer, sizeof(buffer));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(pk, sizeof(pk));
        sodium_memzero(paserk_data, paserk_data_len);
        free(paserk_data);
        memcpy(key, pdk, pdk_len);
        sodium_memzero(pdk, pdk_len);
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
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_local_wrap_len, paserk_key_len - paserk_local_wrap_len,
                NULL, &paserk_data_len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * result = paserk_v3_unwrap(
            &output_len,
            paserk_local_wrap, paserk_local_wrap_len,
            secret, secret_len,
            paserk_data, paserk_data_len);
        if (!result) {
            free(paserk_data);
            return false;
        }
        if (output_len != paseto_v3_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "expecting a private key:  actual:%zu  expected:%d\n",
                output_len, paseto_v3_LOCAL_KEYBYTES);
            free(result);
            free(paserk_data);
            errno = EINVAL;
            return false;
        }
        memcpy(key, result, output_len);
        free(result);
        free(paserk_data);
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
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_local_pw_len, paserk_key_len - paserk_local_pw_len,
                NULL, &paserk_data_len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * result = paserk_v3_password_unwrap(
            &output_len,
            paserk_local_pw, paserk_local_pw_len,
            secret, secret_len,
            paserk_data, paserk_data_len);
        if (!result) {
            free(paserk_data);
            return false;
        }
        if (output_len != paseto_v3_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "expecing a private key:  actual:%zu  expected:%d\n",
                output_len, paseto_v3_LOCAL_KEYBYTES);
            free(result);
            free(paserk_data);
            errno = EINVAL;
            return false;
        }
        memcpy(key, result, output_len);
        free(result);
        free(paserk_data);
        return true;
    }
    errno = EINVAL;
    return false;
}
