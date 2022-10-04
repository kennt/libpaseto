#ifndef LIBPASETO_HELPERS_H
#define LIBPASETO_HELPERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__STDC__) && __STDC__ == 1
#define paseto_static_assert(EXPR, DESC) _Static_assert((EXPR), DESC)

#elif defined(_MSC_VER)
#include <corecrt.h>
#define paseto_static_assert(EXPR, DESC) _STATIC_ASSERT(EXPR)

#else
#error Implement paseto_static_assert for this platform/compiler
#endif


struct pre_auth {
    uint8_t *base;
    uint8_t *current;
};
bool pre_auth_init(struct pre_auth *pa, size_t num_elements, size_t sizes);
void pre_auth_append(struct pre_auth *pa, const uint8_t *data, size_t data_len);


bool key_load_hex(uint8_t *key, size_t key_len, const char *key_hex);
bool key_load_base64(uint8_t *key, size_t key_len, const char *key_base64);


size_t key_calculate_pem_size(const uint8_t *key, size_t key_len);
bool key_to_pem(bool is_public_key,
        const uint8_t *key, size_t key_len,
        uint8_t *output, size_t output_len);
bool key_from_pem(bool is_public_key,
        const uint8_t *key, size_t key_len,
        uint8_t *pem, size_t pem_ken);

char * encode_output(size_t *dest_len,
                     const uint8_t *header, size_t header_len,
                     const uint8_t *body, size_t body_len,
                     const uint8_t *footer, size_t footer_len);

uint8_t * decode_input(
                  const char *encoded, size_t encoded_len,
                  uint8_t **body, size_t *body_len,
                  uint8_t **footer, size_t *footer_len);


/**
 * Allocates and formats the string as a paserk key.
 *
 * Writes out [header][base64-data]
 **/
char *format_paserk_key(const char *header, size_t header_len,
                        uint8_t * key, size_t key_len);

/**
 * Some helpful utilities for base64/hex/bin conversion
 **/
#define BIN_TO_BASE64_MAXLEN(len) sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define BASE64_TO_BIN_MAXLEN(b64_len) (b64_len / 4 * 3)

void _dump_hex(const char * title, const uint8_t *buffer, size_t buffer_len);


uint8_t * paserk_v2_seal_encrypt(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *pubkey, size_t pubkey_len,
    const uint8_t *keydata, size_t keydata_len);

uint8_t * paserk_v2_seal_decrypt(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *seckey, size_t seckey_len,
    const uint8_t *data, size_t data_len);


#endif //LIBPASETO_HELPERS_H
