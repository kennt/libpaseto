#ifndef LIBPASETO_TEST_HELPERS_H
#define LIBPASETO_TEST_HELPERS_H

#include <paseto.h>

#ifdef __cplusplus
extern "C"{
#endif

void nonce_load_hex(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const char *hex);

void nonce_override(const uint8_t buf[paseto_v2_LOCAL_NONCEBYTES]);

void nonce_override_generate_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len, const uint8_t *footer, size_t footer_len);

void generate_reference_nonce(uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES], const uint8_t *message, size_t message_len);

bool load_hex(uint8_t *key, size_t key_len, const char *key_hex);
bool save_hex(char *key_hex, size_t key_hex_len, const uint8_t *key, size_t key_len);

bool load_base64(uint8_t *key, size_t key_len, const char *key_base64);
bool save_base64(char *key_base64, size_t key_base64_len, size_t *real_base64_len,
                 const uint8_t *key, size_t key_len);


#ifdef __cplusplus
};
#endif

#endif
