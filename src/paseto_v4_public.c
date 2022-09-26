#include "paseto.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v4_PUBLIC_PUBLICKEYBYTES == crypto_sign_PUBLICKEYBYTES,
        "PUBLICKEYBYTES mismatch");
paseto_static_assert(
        paseto_v4_PUBLIC_SECRETKEYBYTES == crypto_sign_SECRETKEYBYTES,
        "SECRETKEYBYTES mismatch");
paseto_static_assert(
        paseto_v4_PUBLIC_SEEDBYTES == crypto_sign_SEEDBYTES,
        "SEEDBYTES mismatch");



static const uint8_t header[] = "v4.public.";
static const size_t header_len = sizeof(header) - 1;
static const size_t signature_len = crypto_sign_BYTES;
static const size_t mac_len = 32;

bool paseto_v4_public_load_public_key_hex(
        uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v4_PUBLIC_PUBLICKEYBYTES, key_hex);
}


bool paseto_v4_public_load_public_key_base64(
        uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v4_PUBLIC_PUBLICKEYBYTES, key_base64);
}


bool paseto_v4_public_load_secret_key_hex(
        uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v4_PUBLIC_SECRETKEYBYTES, key_hex);
}


bool paseto_v4_public_load_secret_key_base64(
        uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v4_PUBLIC_SECRETKEYBYTES, key_base64);
}

bool paseto_v4_public_generate_keys(
        const uint8_t *seed, size_t seed_len,
        uint8_t *public_key, size_t public_key_len,
        uint8_t *secret_key, size_t secret_key_len)
{
    if (seed_len != paseto_v4_PUBLIC_SEEDBYTES ||
        public_key_len != paseto_v4_PUBLIC_PUBLICKEYBYTES ||
        secret_key_len != paseto_v4_PUBLIC_SECRETKEYBYTES)
        return false;
    crypto_sign_seed_keypair(public_key, secret_key, seed);
    return true;
}

char *paseto_v4_public_sign(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
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

    /* #1. Ensure that this is the proper key type */
    /* #2. Set h to v4.public */

    const size_t to_encode_len = message_len + signature_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(to_encode, message, message_len);

    /* #3. Pack h,m,f, and i using PAE */
    struct pre_auth pa;
    size_t pre_auth_len;

    {
        if (!pre_auth_init(&pa, 4,
                    header_len +
                    message_len +
                    footer_len +
                    implicit_assertion_len)) {
            free(to_encode);
            errno = ENOMEM;
            return NULL;
        }
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, message, message_len);
        pre_auth_append(&pa, footer, footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    /* #4. Sign using Ed25519 */
    if (crypto_sign_detached(to_encode + message_len, NULL,
                             pa.base, pre_auth_len, key))
    {
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    free(pa.base);

    /* #5. Encode */
    char * output = encode_output(NULL,
                       header, header_len,
                       to_encode, to_encode_len,
                       footer, footer_len);
    if (!output)
    {
        free(to_encode);
        errno = EINVAL;
        return NULL;
    }

    free(to_encode);

    return output;
}

uint8_t *paseto_v4_public_verify(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
        uint8_t **footer, size_t *footer_len,
        const uint8_t *implicit_assertion, size_t implicit_assertion_len) {
    if (!encoded || !message_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (!implicit_assertion) implicit_assertion_len = 0;
    if (!implicit_assertion_len) implicit_assertion = NULL;
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


    /* #4. Decode the payload andf footer */
    const size_t encoded_len = strlen(encoded);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;
    uint8_t * decoded;

    uint8_t *message;
    size_t internal_message_len;
    uint8_t *signature;

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

        signature = body + internal_message_len;
    }

    /* #5. Pack h,m,f, and i using PAE */
    struct pre_auth pa;
    size_t pre_auth_len;

    {
        if (!pre_auth_init(&pa, 4,
                header_len +
                internal_message_len +
                decoded_footer_len +
                implicit_assertion_len)) {
            free(decoded);
            free(decoded_footer);
            errno = ENOMEM;
            return NULL;
        }
        pre_auth_append(&pa, header, header_len);
        pre_auth_append(&pa, decoded, internal_message_len);
        pre_auth_append(&pa, decoded_footer, decoded_footer_len);
        pre_auth_append(&pa, implicit_assertion, implicit_assertion_len);
        pre_auth_len = pa.current - pa.base;
    }

    /* #6. Use Ed25519 to verify the signature */
    if (crypto_sign_verify_detached(
            signature, pa.base, pre_auth_len, key) != 0) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        errno = EINVAL;
        return NULL;
    }

    /* #7. If valid, return the message and footer */
    uint8_t *outmessage = malloc(internal_message_len + 1);
    if (!message) {
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }

    memcpy(outmessage, decoded, internal_message_len);
    message[internal_message_len] = '\0';

    free(pa.base);
    free(decoded);

    if (footer)
        *footer = decoded_footer;
    else
        free(decoded_footer);

    if (footer_len)
        *footer_len = decoded_footer_len;

    *message_len = internal_message_len;

    return outmessage;
}
