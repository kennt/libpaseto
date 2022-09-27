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

#if 0
void dumpHex(const char *title, int lineno, const uint8_t * data, size_t data_len)
{
    std::string data_hex;

    data_hex.resize(2*data_len+1);
    sodium_bin2hex(data_hex.data(), data_hex.length(),
        data, data_len);

    cout << title << " (" << lineno << ") : " << std::hex << data_hex << std::dec << endl;
}
#endif

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
    std::stringstream ostream;
    std::string pubkey_hex;
    std::string seckey_hex;

    seckey_hex.reserve(2*paseto_v3_PUBLIC_SECRETKEYBYTES + 1);
    pubkey_hex.reserve(2*paseto_v3_PUBLIC_PUBLICKEYBYTES + 1);

    /* generate the secret key */
    seckey.Initialize( prng, CryptoPP::ASN1::secp384r1() );

    ostream << std::hex << std::noshowbase << seckey.GetPrivateExponent();
    seckey_hex.append(ostream.str());
    seckey_hex.resize(seckey_hex.length()-1);   // remove 'h' at the end
    std::stringstream().swap(ostream);

    /* ensure that we are zero-filled on the left */
    ostream.width(2*paseto_v3_PUBLIC_SECRETKEYBYTES);
    ostream.fill('0');
    ostream << seckey_hex;
    seckey_hex = ostream.str();
    std::stringstream().swap(ostream);

    /* generate the public key (point compressed) */
    seckey.MakePublicKey(pubkey);
    const ECP::Point& q = pubkey.GetPublicElement();

    pubkey_hex.append(q.y.GetBit(0) ? "03" : "02");

    ostream << std::hex << std::noshowbase << q.x;
    std::string pubkey_data = ostream.str();
    pubkey_data.resize(pubkey_data.length()-1);   // remove 'h' at the end
    std::stringstream().swap(ostream);  // reset ostream

    /* ensure that we are zero-filled on the left */
    ostream.width(2*paseto_v3_PUBLIC_PUBLICKEYBYTES-2);
    ostream.fill('0');
    ostream << pubkey_data;
    pubkey_hex.append(ostream.str());

    /* convert to binary */
    key_load_hex(public_key, public_key_len, pubkey_hex.c_str());
    key_load_hex(secret_key, secret_key_len, seckey_hex.c_str());

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
        const ECP::Point& q = public_key.GetPublicElement();

        /* convert q.x into a hex string */
        std::string pubkey_hex;
        std::stringstream ostream;

        pubkey_hex.reserve(2*paseto_v3_PUBLIC_PUBLICKEYBYTES + 1);
        pubkey_hex.append(q.y.GetBit(0) ? "03" : "02");

        ostream << std::hex << std::noshowbase << q.x;
        std::string pubkey_data = ostream.str();
        pubkey_data.resize(pubkey_data.length()-1);   // remove 'h' at the end

        /* ensure that we are zero-filled on the left */
        std::stringstream().swap(ostream);  // reset ostream
        ostream.width(2*paseto_v3_PUBLIC_PUBLICKEYBYTES-2);
        ostream.fill('0');
        ostream << pubkey_data;
        pubkey_hex.append(ostream.str());

        size_t len = 0;

        /* convert pubkey hex into binary */
        if (sodium_hex2bin(
            pubkey_bin, pubkey_bin_len,
            pubkey_hex.data(), pubkey_hex.length(),
            NULL, &len, NULL) != 0)
        {
            fprintf(stderr, "hex2bin failed dest-len(%zu) src-len(%zu) (%d)\n",
                pubkey_bin_len, pubkey_hex.length(), __LINE__);
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
                footer_len +
                implicit_assertion_len
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

        size_t siglen = signer.SignMessage(prng,
                            pa.base, pre_auth_len,
                            sig);
        if (siglen != signature_len)
        {
            fprintf(stderr, "unexpected signature length: actual:%zu expected:%zu\n",
                siglen, signature_len);
            errno = EINVAL;
            return NULL;
        }
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
        fprintf(stderr, "encode_output failed (%d)\n", __LINE__);
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
        const uint8_t *implicit_assertion, size_t implicit_assertion_len)
{
    if (footer) *footer = NULL;
    if (footer_len) *footer_len = 0;

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
            free(pa.base);
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }
    free(pa.base);

    /* #7. If valid, return m */

    /* zero out the signature portion of the decoded buffer */
    memset(sig, 0x00, signature_len);

    if (footer)
        *footer = decoded_footer;
    else
        free(decoded_footer);

    if (footer_len)
        *footer_len = decoded_footer_len;

    *message_len = internal_message_len;

    return message;
}
