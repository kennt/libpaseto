#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v2_PUBLIC_PUBLICKEYBYTES == crypto_sign_PUBLICKEYBYTES,
        "PUBLICKEYBYTES mismatch");
paseto_static_assert(
        paseto_v2_PUBLIC_SECRETKEYBYTES == crypto_sign_SECRETKEYBYTES,
        "SECRETKEYBYTES mismatch");



static const uint8_t header[] = "v2.public.";
static const size_t header_len = sizeof(header) - 1;
static const size_t signature_len = crypto_sign_BYTES;


bool paseto_v2_public_load_public_key_hex(
        uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v2_PUBLIC_PUBLICKEYBYTES, key_hex);
}


bool paseto_v2_public_load_public_key_base64(
        uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v2_PUBLIC_PUBLICKEYBYTES, key_base64);
}


bool paseto_v2_public_load_secret_key_hex(
        uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v2_PUBLIC_SECRETKEYBYTES, key_hex);
}


bool paseto_v2_public_load_secret_key_base64(
        uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v2_PUBLIC_SECRETKEYBYTES, key_base64);
}

bool paseto_v2_public_generate_keys(
        const uint8_t *seed, size_t seed_len,
        uint8_t *public_key, size_t public_key_len,
        uint8_t *secret_key, size_t secret_key_len)
{
    if (public_key_len != paseto_v2_PUBLIC_PUBLICKEYBYTES ||
        secret_key_len != paseto_v2_PUBLIC_SECRETKEYBYTES)
        return false;
    if (seed == NULL || seed_len == 0)
        crypto_sign_keypair(public_key, secret_key);
    else
        crypto_sign_seed_keypair(public_key, secret_key, seed);
    return true;
}

char *paseto_v2_public_sign(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
        const uint8_t *footer, size_t footer_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;

    const size_t to_encode_len = message_len + signature_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(to_encode, message, message_len);

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3, header_len + message_len + footer_len)) {
        sodium_memzero(to_encode, to_encode_len);
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, message, message_len);
    pre_auth_append(&pa, footer, footer_len);
    size_t pre_auth_len = pa.current - pa.base;

    uint8_t *ct = to_encode + message_len;
    crypto_sign_detached(ct, NULL, pa.base, pre_auth_len, key);

    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    size_t encoded_len = BIN_TO_BASE64_MAXLEN(to_encode_len) - 1; // minus included trailing NULL byte
    size_t output_len = header_len + encoded_len;
    if (footer) output_len += BIN_TO_BASE64_MAXLEN(footer_len) - 1 + 1; // minus included NULL byte, plus '.' separator
    output_len += 1; // trailing NULL byte
    char *output = malloc(output_len);
    char *output_current = output;
    size_t output_len_remaining = output_len;
    if (!output) {
        sodium_memzero(to_encode, to_encode_len);
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    memcpy(output_current, header, header_len);
    output_current += header_len;
    output_len_remaining -= header_len;
    sodium_bin2base64(
            output_current, output_len_remaining,
            to_encode, to_encode_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_len = strlen(output_current);
    output_current += encoded_len;
    output_len_remaining -= encoded_len;

    sodium_memzero(to_encode, to_encode_len);
    free(to_encode);

    if (footer) {
        *output_current++ = '.';
        output_len_remaining--;
        sodium_bin2base64(
                output_current, output_len_remaining,
                footer, footer_len,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    }

    return output;
}

uint8_t *paseto_v2_public_verify(
        const char *encoded, size_t *message_len,
        const uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
        uint8_t **footer, size_t *footer_len) {
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
        sodium_memzero(decoded, decoded_maxlen);
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
            sodium_memzero(decoded, decoded_maxlen);
            free(decoded);
            sodium_memzero(decoded_footer, encoded_footer_len);
            free(decoded_footer);
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + internal_message_len + decoded_footer_len)) {
        sodium_memzero(decoded, decoded_maxlen);
        free(decoded);
        sodium_memzero(decoded_footer, encoded_footer_len);
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
        sodium_memzero(decoded, decoded_maxlen);
        sodium_memzero(decoded_footer, encoded_footer_len);
        sodium_memzero(pa.base, pre_auth_len);
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    if (crypto_sign_verify_detached(
            signature, pa.base, pre_auth_len, key) != 0) {
        sodium_memzero(decoded, decoded_maxlen);
        sodium_memzero(decoded_footer, encoded_footer_len);
        sodium_memzero(pa.base, pre_auth_len);
        sodium_memzero(message, internal_message_len + 1);
        free(decoded);
        free(decoded_footer);
        free(pa.base);
        free(message);
        errno = EINVAL;
        return NULL;
    }

    memcpy(message, decoded, internal_message_len);
    message[internal_message_len] = '\0';

    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);
    sodium_memzero(decoded, decoded_maxlen);
    free(decoded);

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            sodium_memzero(decoded_footer, encoded_footer_len);
            free(decoded_footer);
            sodium_memzero(message, internal_message_len + 1);
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

    sodium_memzero(decoded_footer, encoded_footer_len);
    free(decoded_footer);

    *message_len = internal_message_len;

    return message;
}


static const char paserk_public[] = "k2.public.";
static const size_t paserk_public_len = sizeof(paserk_public) - 1;
static const char paserk_pid[] = "k2.pid.";
static const size_t paserk_pid_len = sizeof(paserk_pid) - 1;


char * paseto_v2_public_key_to_paserk(
    uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_public, paserk_public_len) == 0)
    {
        return format_paserk_key(paserk_public, paserk_public_len,
                                 key, paseto_v2_PUBLIC_PUBLICKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_pid, paserk_pid_len) == 0)
    {
        char * paserk_key = paseto_v2_public_key_to_paserk(key, paserk_public, NULL, 0, NULL);
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

bool paseto_v2_public_key_from_paserk(
    uint8_t key[paseto_v2_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_public, paserk_public_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v2_PUBLIC_PUBLICKEYBYTES,
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


static const char paserk_secret[] = "k2.secret.";
static const size_t paserk_secret_len = sizeof(paserk_secret) - 1;
static const char paserk_sid[] = "k2.sid.";
static const size_t paserk_sid_len = sizeof(paserk_sid) - 1;
static const char paserk_secret_wrap[] = "k2.secret-wrap.pie.";
static const size_t paserk_secret_wrap_len = sizeof(paserk_secret_wrap) - 1;
static const char paserk_secret_pw[] = "k2.secret-pw.";
static const size_t paserk_secret_pw_len = sizeof(paserk_secret_pw) - 1;


char * paseto_v2_secret_key_to_paserk(
    uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_secret, paserk_secret_len) == 0)
    {
        return format_paserk_key(paserk_secret, paserk_secret_len,
                                 key, paseto_v2_PUBLIC_SECRETKEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_sid, paserk_sid_len) == 0)
    {
        char * paserk_key = paseto_v2_secret_key_to_paserk(key, paserk_secret, NULL, 0, NULL);
        size_t to_encode_len = paserk_pid_len + strlen(paserk_key);
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
                    key, paseto_v2_PUBLIC_SECRETKEYBYTES);
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
                    key, paseto_v2_PUBLIC_SECRETKEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_secret_pw, paserk_secret_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}

bool paseto_v2_secret_key_from_paserk(
    uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_secret, paserk_secret_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v2_PUBLIC_SECRETKEYBYTES,
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

        if (output_len != paseto_v2_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                output_len, paseto_v2_PUBLIC_SECRETKEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v2_PUBLIC_SECRETKEYBYTES);

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

        if (output_len != paseto_v2_PUBLIC_SECRETKEYBYTES)
        {
            fprintf(stderr, "unwrapped key length mismatch: actual:%zu expected:%u\n",
                output_len, paseto_v2_PUBLIC_SECRETKEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v2_PUBLIC_SECRETKEYBYTES);

        free(pdk);
        return true;
    }
    errno = EINVAL;
    return false;
}
