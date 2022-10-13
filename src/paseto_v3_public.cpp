extern "C" {
#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>
};

#include <iostream>
#include <sstream>
using std::cout;
using std::cerr;
using std::endl;

#include "cryptopp/cryptlib.h"
#include "cryptopp/algebra.h"
using CryptoPP::Integer;

#include "cryptopp/oids.h"

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA_RFC6979;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/sha.h"
using CryptoPP::SHA384;

#include "helpers.hpp"


static const uint8_t header[] = "v3.public.";
static const size_t header_len = sizeof(header) - 1;
static const size_t signature_len = 96;

bool paseto_v3_public_load_public_key_hex(
        uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v3_PUBLIC_PUBLICKEYBYTES, key_hex);
}


bool paseto_v3_public_load_public_key_base64(
        uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v3_PUBLIC_PUBLICKEYBYTES, key_base64);
}


bool paseto_v3_public_load_secret_key_hex(
        uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v3_PUBLIC_SECRETKEYBYTES, key_hex);
}


bool paseto_v3_public_load_secret_key_base64(
        uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v3_PUBLIC_SECRETKEYBYTES, key_base64);
}


bool paseto_v3_public_generate_keys(
        const uint8_t *seed, size_t seed_len,
        uint8_t *public_key, size_t public_key_len,
        uint8_t *secret_key, size_t secret_key_len)
{
    if (public_key_len != paseto_v3_PUBLIC_PUBLICKEYBYTES ||
        secret_key_len != paseto_v3_PUBLIC_SECRETKEYBYTES)
    {
        errno = EINVAL;
        return false;
    }

    ECDSA_RFC6979<ECP,SHA384>::PrivateKey seckey;
    ECDSA_RFC6979<ECP,SHA384>::PublicKey pubkey;
    AutoSeededRandomPool prng;
    std::string pubkey_hex;
    std::string seckey_hex;

    /* generate the secret key */
    seckey.Initialize( prng, CryptoPP::ASN1::secp384r1() );
    seckey_hex = p384_privatekey_to_hex(seckey);

    /* generate the public key (point compressed) */
    seckey.MakePublicKey(pubkey);
    pubkey_hex = p384_publickey_to_hex(pubkey);

    /* convert to binary */
    key_load_hex(public_key, public_key_len, pubkey_hex.c_str());
    key_load_hex(secret_key, secret_key_len, seckey_hex.c_str());

    sodium_memzero(seckey_hex.data(), seckey_hex.length());
    sodium_memzero(pubkey_hex.data(), pubkey_hex.length());

    return true;
}

char *paseto_v3_public_sign(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
        const uint8_t *footer, size_t footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;
    if (!implicit_assertion) implicit_assertion_len = 0;
    if (!implicit_assertion_len) implicit_assertion = NULL;

    ECDSA_RFC6979<ECP,SHA384>::PrivateKey secret_key;
    ECDSA_RFC6979<ECP,SHA384>::PublicKey public_key;
    AutoSeededRandomPool prng;

    /* #1. Extract and check the secret key */
    {
        /* Initialize the sk */
        Integer x {key, paseto_v3_PUBLIC_SECRETKEYBYTES};

        secret_key.Initialize(CryptoPP::ASN1::secp384r1(), x);
        
        if (!secret_key.Validate(prng, 3))
        {
            fprintf(stderr, "secret key validate() failed (%d)\n", __LINE__);
            errno = EINVAL;
            return NULL;
        }
    }

    /* #2. set header */

    /* #3. pack pk,h,m,f, and i using PAE, then sign */
    uint8_t pubkey_bin[paseto_v3_PUBLIC_PUBLICKEYBYTES];
    size_t pubkey_bin_len = sizeof(pubkey_bin);

    {
        /* get the pk from sk */
        secret_key.MakePublicKey(public_key);

        /* get pubkey as point-compressed */
        std::string pubkey_hex;
        pubkey_hex = p384_publickey_to_hex(public_key);

        size_t len = 0;

        /* convert pubkey hex into binary */
        if (sodium_hex2bin(
            pubkey_bin, pubkey_bin_len,
            pubkey_hex.data(), pubkey_hex.length(),
            NULL, &len, NULL) != 0)
        {
            fprintf(stderr, "hex2bin failed dest-len(%zu) src-len(%zu) (%d)\n",
                pubkey_bin_len, pubkey_hex.length(), __LINE__);
            sodium_memzero(pubkey_hex.data(), pubkey_hex.length());
            errno = EINVAL;
            return NULL;
        }
        sodium_memzero(pubkey_hex.data(), pubkey_hex.length());
    }

    struct pre_auth pa;
    size_t pre_auth_len;

    {
        /* build the pa_auth */
        if (!pre_auth_init(&pa, 5,
                pubkey_bin_len +
                header_len +
                message_len +
                footer_len +
                implicit_assertion_len
                ))
        {
            sodium_memzero(pubkey_bin, pubkey_bin_len);
            errno = EINVAL;
            return NULL;
        }
        pre_auth_append(&pa, pubkey_bin, pubkey_bin_len);
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, message, message_len);
        pre_auth_append(&pa, footer, footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    uint8_t sig[signature_len];

    /* #4. Sign using ECDSA over P-384 and SHA-384 */
    {
        ECDSA_RFC6979<ECP,SHA384>::Signer signer( secret_key );

        size_t siglen = signer.SignMessage(prng,
                            pa.base, pre_auth_len,
                            sig);
        if (siglen != signature_len)
        {
            fprintf(stderr, "unexpected signature length: actual:%zu expected:%zu\n",
                siglen, signature_len);
            sodium_memzero(sig, sizeof(sig));
            sodium_memzero(pubkey_bin, pubkey_bin_len);
            sodium_memzero(pa.base, pre_auth_len);
            free(pa.base);
            errno = EINVAL;
            return NULL;
        }
    }
    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    /* #5. Create the output */
    size_t to_encode_len = message_len + signature_len;
    uint8_t * to_encode = (uint8_t *) malloc(to_encode_len);
    if (to_encode == NULL)
    {
        sodium_memzero(sig, sizeof(sig));
        sodium_memzero(pubkey_bin, pubkey_bin_len);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(to_encode, message, message_len);
    memcpy(to_encode + message_len, sig, signature_len);

    char * output = encode_output(NULL,
                       header, header_len,
                       to_encode, to_encode_len,
                       footer, footer_len);
    if (output == NULL)
    {
        fprintf(stderr, "encode_output failed (%d)\n", __LINE__);
        sodium_memzero(sig, sizeof(sig));
        sodium_memzero(pubkey_bin, pubkey_bin_len);
        sodium_memzero(to_encode, to_encode_len);
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    sodium_memzero(sig, sizeof(sig));
    sodium_memzero(pubkey_bin, pubkey_bin_len);
    sodium_memzero(to_encode, to_encode_len);
    free(to_encode);

    return output;
}

uint8_t *paseto_v3_public_verify(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len)
{
    if (footer) *footer = NULL;
    if (footer_len) *footer_len = 0;

    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (strlen(encoded) < header_len + BIN_TO_BASE64_MAXLEN(signature_len) - 1
            || memcmp(encoded, header, header_len) != 0) {
        errno = EINVAL;
        return NULL;
    }

    encoded += header_len;
    size_t encoded_len = strlen(encoded);

    /* #1. Create and check the public key */
    ECDSA_RFC6979<ECP, SHA384>::PublicKey public_key;
    AutoSeededRandomPool prng;

    {
        public_key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp384r1());

        ECP::Point point;
        public_key.GetGroupParameters().GetCurve().DecodePoint (point, key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
        public_key.SetPublicElement(point);

        // validate the pk
        if (!public_key.Validate(prng, 3))
        {
            fprintf(stderr, "public key validate() failed %d\n", __LINE__);
            errno = EINVAL;
            return NULL;
        }
    }

    /* #2. May check the footer */
    /* #3. Verify the message header */

    /* #4. Decode the payload */
    uint8_t *decoded;
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;
    uint8_t *message;
    size_t internal_message_len;
    uint8_t *sig;
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

        message = body;
        internal_message_len = body_len - signature_len;
        sig = body + internal_message_len;
    }

    /* #5. Pack pk,h,m,f, and i using PAE */
    struct pre_auth pa;
    size_t pre_auth_len;

    {
        if (!pre_auth_init(&pa, 5,
                paseto_v3_PUBLIC_PUBLICKEYBYTES +
                header_len +
                internal_message_len +
                decoded_footer_len +
                implicit_assertion_len))
        {
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(decoded_footer);
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }
        pre_auth_append(&pa, key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, message, internal_message_len);
        pre_auth_append(&pa, decoded_footer, decoded_footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    /* #6. Use ECDSA to verify the signature */
    {
        ECDSA_RFC6979<ECP,SHA384>::Verifier verifier(public_key);
        if (!verifier.VerifyMessage(pa.base, pre_auth_len,
                sig, signature_len))
        {
            fprintf(stderr, "verify() failed %d\n", __LINE__);
            sodium_memzero(pa.base, pre_auth_len);
            sodium_memzero(decoded_footer, decoded_footer_len);
            sodium_memzero(decoded, body_len);
            free(pa.base);
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }
    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    /* #7. If valid, return m */

    /* zero out the signature portion of the decoded buffer */
    memset(sig, 0x00, signature_len);

    if (footer)
        *footer = decoded_footer;
    else
    {
        sodium_memzero(decoded_footer, decoded_footer_len);
        free(decoded_footer);
    }

    if (footer_len)
        *footer_len = decoded_footer_len;

    *message_len = internal_message_len;

    return message;
}


static const char paserk_public[] = "k3.public.";
static const size_t paserk_public_len = sizeof(paserk_public) - 1;
static const char paserk_pid[] = "k3.pid.";
static const size_t paserk_pid_len = sizeof(paserk_pid) - 1;


char * paseto_v3_public_key_to_paserk(
    uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_public, paserk_public_len) == 0)
    {
        return format_paserk_key(paserk_public, paserk_public_len,
                                 key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_pid, paserk_pid_len) == 0)
    {
        char * paserk_key = paseto_v3_public_key_to_paserk(key, paserk_public, NULL, 0, NULL);
        size_t to_encode_len = paserk_pid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_pid, paserk_pid_len);
        memcpy(to_encode+paserk_pid_len, paserk_key, to_encode_len - paserk_pid_len);

        uint8_t digest[48];
        SHA384 sha;
        sha.CalculateDigest(digest, to_encode, to_encode_len);

        uint8_t hash[33];
        memcpy(hash, digest, 33);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_pid, paserk_pid_len,
                                 hash, sizeof(hash));
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v3_public_key_from_paserk(
    uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_public, paserk_public_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v3_PUBLIC_PUBLICKEYBYTES,
                paserk_key + paserk_public_len, paserk_key_len - paserk_public_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            if (len != paseto_v3_PUBLIC_PUBLICKEYBYTES)
            {
                fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                    len, paseto_v3_PUBLIC_PUBLICKEYBYTES);
                sodium_memzero(key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
                errno = EINVAL;
                return false;
            }
            return true;
        }
        sodium_memzero(key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
    }
    errno = EINVAL;
    return false;
}


static const char paserk_secret[] = "k3.secret.";
static const size_t paserk_secret_len = sizeof(paserk_secret) - 1;
static const char paserk_sid[] = "k3.sid.";
static const size_t paserk_sid_len = sizeof(paserk_sid) - 1;
static const char paserk_secret_wrap[] = "k3.secret-wrap.pie.";
static const size_t paserk_secret_wrap_len = sizeof(paserk_secret_wrap) - 1;
static const char paserk_secret_pw[] = "k3.secret-pw.";
static const size_t paserk_secret_pw_len = sizeof(paserk_secret_pw) - 1;


char * paseto_v3_secret_key_to_paserk(
    uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_secret, paserk_secret_len) == 0)
    {
        return format_paserk_key(paserk_secret, paserk_secret_len,
                                 key, paseto_v3_PUBLIC_SECRETKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_sid, paserk_sid_len) == 0)
    {
        char * paserk_key = paseto_v3_secret_key_to_paserk(key, paserk_secret, NULL, 0, NULL);
        size_t to_encode_len = paserk_sid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_sid, paserk_sid_len);
        memcpy(to_encode+paserk_sid_len, paserk_key, to_encode_len - paserk_sid_len);

        uint8_t digest[48];
        SHA384 sha;
        sha.CalculateDigest(digest, to_encode, to_encode_len);

        uint8_t hash[33];
        memcpy(hash, digest, 33);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_sid, paserk_sid_len,
                                 hash, sizeof(hash));
    }
    else if (strncmp(paserk_id, paserk_secret_wrap, paserk_secret_wrap_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v3_wrap(
                &out_len,
                paserk_secret_wrap, paserk_secret_wrap_len,
                secret, secret_len,
                key, paseto_v3_PUBLIC_SECRETKEYBYTES);
        if (!out) {
            errno = ENOMEM;
            return NULL;
        }
        char * result = format_paserk_key(paserk_secret_wrap, paserk_secret_wrap_len,
                                 out, out_len);
        paseto_free(out);
        return result;
    }
    else if (strncmp(paserk_id, paserk_secret_pw, paserk_secret_pw_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v3_password_wrap(
                    &out_len,
                    paserk_secret_pw, paserk_secret_pw_len,
                    secret, secret_len,
                    key, paseto_v3_PUBLIC_SECRETKEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_secret_pw, paserk_secret_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v3_secret_key_from_paserk(
    uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_secret, paserk_secret_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v3_PUBLIC_SECRETKEYBYTES,
                paserk_key + paserk_secret_len, strlen(paserk_key) - paserk_secret_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            if (len != paseto_v3_PUBLIC_SECRETKEYBYTES)
            {
                fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                    len, paseto_v3_PUBLIC_SECRETKEYBYTES);
                sodium_memzero(key, paseto_v3_PUBLIC_SECRETKEYBYTES);
                errno = EINVAL;
                return false;
            }
            return true;
        }
        sodium_memzero(key, paseto_v3_PUBLIC_SECRETKEYBYTES);
    }
    else if (strncmp(paserk_key, paserk_secret_wrap, paserk_secret_wrap_len) == 0)
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
                paserk_key + paserk_secret_wrap_len, paserk_key_len - paserk_secret_wrap_len,
                NULL, &paserk_data_len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * result = paserk_v3_unwrap(
            &output_len,
            paserk_secret_wrap, paserk_secret_wrap_len,
            secret, secret_len,
            paserk_data, paserk_data_len);
        if (!result) {
            free(paserk_data);
            return false;
        }
        if (output_len != paseto_v3_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "expecing a private key:  actual:%zu  expected:%d\n",
                output_len, paseto_v3_PUBLIC_SECRETKEYBYTES);
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
    else if (strncmp(paserk_key, paserk_secret_pw, paserk_secret_pw_len) == 0)
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
                paserk_key + paserk_secret_pw_len, paserk_key_len - paserk_secret_pw_len,
                NULL, &paserk_data_len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * result = paserk_v3_password_unwrap(
            &output_len,
            paserk_secret_pw, paserk_secret_pw_len,
            secret, secret_len,
            paserk_data, paserk_data_len);
        if (!result) {
            free(paserk_data);
            return false;
        }
        if (output_len != paseto_v3_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "expecting a private key:  actual:%zu  expected:%d\n",
                output_len, paseto_v3_PUBLIC_SECRETKEYBYTES);
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
