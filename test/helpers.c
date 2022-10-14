#include "helpers.h"
#include <memory.h>
#include <assert.h>
#include <sodium.h>
#include <errno.h>

static bool override_enabled = false;
static uint8_t override_value[paseto_v2_LOCAL_NONCEBYTES];

void nonce_load_hex(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const char *hex) {
    if (!nonce || !hex || strlen(hex) != 2 * paseto_v2_LOCAL_NONCEBYTES) {
        fprintf(stderr, "nonce_load_hex called with invalid hex string length "
                        "or null pointer");
        abort();
    }
    assert(sodium_hex2bin(nonce, paseto_v2_LOCAL_NONCEBYTES, hex, strlen(hex),
            NULL, NULL, NULL) == 0);
}

void nonce_override(const uint8_t buf[paseto_v2_LOCAL_NONCEBYTES]) {
    override_enabled = (buf != NULL);
    if (!override_enabled) return;
    memcpy(override_value, buf, paseto_v2_LOCAL_NONCEBYTES);
}

void nonce_override_generate_nonce(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len) {
    if (!nonce || !message) {
        fprintf(stderr, "generate_nonce called with null pointer");
        abort();
    }
    if (override_enabled) {
        memcpy(nonce, override_value, paseto_v2_LOCAL_NONCEBYTES);
    } else {
        default_generate_nonce(nonce, message, message_len, footer, footer_len);
    }
}


void generate_reference_nonce(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len) {
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nonce, paseto_v2_LOCAL_NONCEBYTES,
            paseto_v2_LOCAL_NONCEBYTES);
    crypto_generichash_blake2b_update(&state, message, message_len);
    crypto_generichash_blake2b_final(&state, nonce, paseto_v2_LOCAL_NONCEBYTES);
}

bool load_hex(uint8_t *key, size_t key_len, const char *key_hex) {
    if (!key || !key_hex) {
        errno = EINVAL;
        return false;
    }
    size_t len;
    if (sodium_hex2bin(
            key, key_len,
            key_hex, strlen(key_hex),
            NULL, &len, NULL) != 0) {
        errno = EINVAL;
        return false;
    }
    if (len != key_len) {
        errno = EINVAL;
        return false;
    }
    return true;
}

bool save_hex(char *key_hex, size_t key_hex_len, const uint8_t *key, size_t key_len)
{
    if (key_hex_len < (2*key_len + 1))
        return false;
    sodium_bin2hex(key_hex, key_hex_len, key, key_len);
    return true;
}


#define BIN_TO_BASE64_MAXLEN(len) sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define BASE64_TO_BIN_MAXLEN(b64_len) (b64_len / 4 * 3)

bool load_base64(uint8_t *key, size_t key_len, const char *key_base64)
{
    if (!key || !key_base64) {
        errno = EINVAL;
        return false;
    }

    if (key_len < BASE64_TO_BIN_MAXLEN(strlen(key_base64)))
    {
        errno = ENOMEM;
        return false;
    }

    size_t len;
    if (sodium_base642bin(
            key, key_len,
            key_base64, strlen(key_base64),
            NULL, &len, NULL,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        errno = EINVAL;
        return false;
    }
    if (len != key_len) {
        sodium_memzero(key, key_len);
        errno = EINVAL;
        return false;
    }
    return true;
}

bool save_base64(char *key_base64, size_t key_base64_len, size_t *real_base64_len,
                 const uint8_t *key, size_t key_len)
{
    sodium_bin2base64(
            key_base64, key_base64_len,
            key, key_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    *real_base64_len = strlen(key_base64);
    return true;
}
