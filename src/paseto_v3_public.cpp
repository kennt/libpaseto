extern "C" {
#include "paseto.h"
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
using namespace CryptoPP::ASN1;

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

#if 0
paseto_static_assert(
        paseto_v3_PUBLIC_PUBLICKEYBYTES == crypto_sign_PUBLICKEYBYTES,
        "PUBLICKEYBYTES mismatch");
paseto_static_assert(
        paseto_v3_PUBLIC_SECRETKEYBYTES == crypto_sign_SECRETKEYBYTES,
        "SECRETKEYBYTES mismatch");
#endif


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

bool paseto_v3_is_public_key(
        uint8_t *key, size_t key_len)
{
    if (key_len != paseto_v3_PUBLIC_PUBLICKEYBYTES)
        return false;
    return true;
    //return !paseto_v3_is_secret_key(key, key_len);
}

bool paseto_v3_is_secret_key(
        uint8_t *key, size_t key_len)
{
    if (key_len != paseto_v3_PUBLIC_SECRETKEYBYTES)
        return false;
    return true;
}

bool paseto_v3_public_generate_keys(
        const uint8_t *seed, size_t seed_len,
        uint8_t *public_key, size_t public_key_len,
        uint8_t *secret_key, size_t secret_key_len)
{
    if (seed_len != crypto_sign_SEEDBYTES ||
        public_key_len != crypto_sign_PUBLICKEYBYTES ||
        secret_key_len != crypto_sign_SECRETKEYBYTES)
    {
        errno = EINVAL;
        return false;
    }
    crypto_sign_seed_keypair(public_key, secret_key, seed);
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
            std::cerr << "secret key validation failed " << __LINE__ << std::endl;
            errno = EINVAL;
            return NULL;
        }
    }

    /* #2. set header */

    /* #3. pack pk,h,m,f, and i using PAE, then sign */
    std::string pubkey_hex;
    uint8_t pubkey_bin[paseto_v3_PUBLIC_PUBLICKEYBYTES];
    size_t pubkey_bin_len = sizeof(pubkey_bin);

    {
        /* get the pk from sk */
        secret_key.MakePublicKey(public_key);

        /* get pubkey as point-compressed */
        const ECP::Point& q = public_key.GetPublicElement();

        std::stringstream ostream;
        ostream << (q.y.GetBit(0) ? "03" : "02") << std::hex << std::noshowbase << q.x;
        pubkey_hex = ostream.str();

        /* remove the 'h' at the end of the string */
        pubkey_hex.resize(pubkey_hex.length()-1);

        size_t len = 0;

        /* convert pubkey hex into binary */
        if (sodium_hex2bin(
            pubkey_bin, pubkey_bin_len,
            pubkey_hex.data(), pubkey_hex.length(),
            NULL, &len, NULL) != 0)
        {
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    size_t pre_auth_len;

    {
        /* build the pa_auth */
        if (!pre_auth_init(&pa, 5,
                pubkey_bin_len +
                header_len +
                message_len +
                footer_len + // footer
                implicit_assertion_len // implicit
                ))
        {
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

        signer.SignMessage(prng,
                           pa.base, pre_auth_len,
                           sig);
    }
    free(pa.base);

    /* #5. Create the output */
    size_t to_encode_len = message_len + signature_len;
    uint8_t * to_encode = (uint8_t *) malloc(to_encode_len);
    if (to_encode == NULL)
    {
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
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    free(to_encode);

    return output;
}

uint8_t *paseto_v3_public_verify(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (strlen(encoded) < header_len + sodium_base64_ENCODED_LEN(
                signature_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1
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
 
        //StringSource ss (key, true, new CryptoPP::HexDecoder);
        //public_key.GetGroupParameters().GetCurve().DecodePoint (point, ss, ss.MaxRetrievable());
        public_key.GetGroupParameters().GetCurve().DecodePoint (point, key, paseto_v3_PUBLIC_PUBLICKEYBYTES);
        public_key.SetPublicElement(point);

        // validate the pk
        if (!public_key.Validate(prng, 3))
        {
            errno = EINVAL;
            return NULL;
        }
    }

    const char *encoded_end = strchr(encoded, '.');
    if (!encoded_end) encoded_end = encoded + encoded_len;
    const size_t decoded_maxlen = encoded_end - encoded;
    uint8_t *decoded = (uint8_t *) malloc(decoded_maxlen);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    size_t decoded_len;
    const char *encoded_footer;
    if (sodium_base642bin(
            decoded, decoded_maxlen,
            encoded, encoded_len,
            NULL, &decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    const size_t internal_message_len = decoded_len - signature_len;
    const uint8_t *signature = decoded + internal_message_len;

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        decoded_footer = (uint8_t *) malloc(encoded_footer_len);

        if (sodium_base642bin(
                decoded_footer, encoded_len - decoded_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            free(decoded);
            free(decoded_footer);
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + internal_message_len + decoded_footer_len)) {
        free(decoded);
        free(decoded_footer);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, decoded, internal_message_len);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    size_t pre_auth_len = pa.current - pa.base;


    uint8_t *message = (uint8_t *) malloc(internal_message_len + 1);
    if (!message) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    if (crypto_sign_verify_detached(
            signature, pa.base, pre_auth_len, key) != 0) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        free(message);
        errno = EINVAL;
        return NULL;
    }

    memcpy(message, decoded, internal_message_len);
    message[internal_message_len] = '\0';

    free(pa.base);
    free(decoded);

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = (uint8_t *) malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            free(decoded_footer);
            free(message);
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

    free(decoded_footer);

    *message_len = internal_message_len;

    return message;
}
