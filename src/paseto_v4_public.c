#include "paseto.h"
#include "paserk.h"
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


static const char paserk_public[] = "k4.public.";
static const size_t paserk_public_len = sizeof(paserk_public) - 1;
static const char paserk_pid[] = "k4.pid.";
static const size_t paserk_pid_len = sizeof(paserk_pid) - 1;


char * paseto_v4_public_key_to_paserk(
    uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_public, paserk_public_len) == 0)
    {
        return format_paserk_key(paserk_public, paserk_public_len,
                                 key, paseto_v4_PUBLIC_PUBLICKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_pid, paserk_pid_len) == 0)
    {
        char * paserk_key = paseto_v4_public_key_to_paserk(key, paserk_public, NULL, 0, NULL);
        size_t to_encode_len = paserk_pid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_pid, paserk_pid_len);
        memcpy(to_encode+paserk_pid_len, paserk_key, to_encode_len - paserk_pid_len);

        uint8_t hash[33];
        crypto_generichash(hash, sizeof(hash), to_encode, to_encode_len, NULL, 0);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_pid, paserk_pid_len,
                                 hash, sizeof(hash));
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v4_public_key_from_paserk(
    uint8_t key[paseto_v4_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_public, paserk_public_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v4_PUBLIC_PUBLICKEYBYTES,
                paserk_key + paserk_public_len, paserk_key_len - paserk_public_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            return true;
        }
    }
    errno = EINVAL;
    return false;
}


static const char paserk_secret[] = "k4.secret.";
static const size_t paserk_secret_len = sizeof(paserk_secret) - 1;
static const char paserk_sid[] = "k4.sid.";
static const size_t paserk_sid_len = sizeof(paserk_sid) - 1;
static const char paserk_secret_wrap[] = "k4.secret-wrap.pie.";
static const size_t paserk_secret_wrap_len = sizeof(paserk_secret_wrap) - 1;
static const char paserk_secret_pw[] = "k4.secret-pw.";
static const size_t paserk_secret_pw_len = sizeof(paserk_secret_pw) - 1;


char * paseto_v4_secret_key_to_paserk(
    uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_secret, paserk_secret_len) == 0)
    {
        return format_paserk_key(paserk_secret, paserk_secret_len,
                                 key, paseto_v4_PUBLIC_SECRETKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_sid, paserk_sid_len) == 0)
    {
        char * paserk_key = paseto_v4_secret_key_to_paserk(key, paserk_secret, NULL, 0, NULL);
        size_t to_encode_len = paserk_sid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_sid, paserk_sid_len);
        memcpy(to_encode+paserk_sid_len, paserk_key, to_encode_len - paserk_sid_len);

        uint8_t hash[33];
        crypto_generichash(hash, sizeof(hash), to_encode, to_encode_len, NULL, 0);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_sid, paserk_sid_len,
                                 hash, sizeof(hash));
    }
    else if (strncmp(paserk_id, paserk_secret_wrap, paserk_secret_wrap_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_wrap(
                    &out_len,
                    paserk_secret_wrap, paserk_secret_wrap_len,
                    secret, secret_len,
                    key, paseto_v4_PUBLIC_SECRETKEYBYTES);
        char * output = format_paserk_key(paserk_secret_wrap, paserk_secret_wrap_len,
                                out, out_len);
        free(out);
        return output;
    }
    else if (strncmp(paserk_id, paserk_secret_pw, paserk_secret_pw_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_password_wrap(
                    &out_len,
                    paserk_secret_pw, paserk_secret_pw_len,
                    secret, secret_len,
                    key, paseto_v4_PUBLIC_SECRETKEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_secret_pw, paserk_secret_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v4_secret_key_from_paserk(
    uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_secret, paserk_secret_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v4_PUBLIC_SECRETKEYBYTES,
                paserk_key + paserk_secret_len, strlen(paserk_key) - paserk_secret_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            return true;
        }
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
        size_t len;
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_secret_wrap_len, paserk_key_len - paserk_secret_wrap_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_unwrap(
                        &output_len,
                        paserk_secret_wrap, paserk_secret_wrap_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v4_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                output_len, paseto_v4_PUBLIC_SECRETKEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v4_PUBLIC_SECRETKEYBYTES);

        free(pdk);
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
        size_t len;
        if (sodium_base642bin(
                paserk_data, paserk_data_len,
                paserk_key + paserk_secret_pw_len, paserk_key_len - paserk_secret_pw_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_password_unwrap(
                        &output_len,
                        paserk_secret_pw, paserk_secret_pw_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v4_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "unwrapped key length mismatch: actual:%zu expected:%u\n",
                output_len, paseto_v4_PUBLIC_SECRETKEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v4_PUBLIC_SECRETKEYBYTES);

        free(pdk);
        return true;
    }
    errno = EINVAL;
    return false;
}
