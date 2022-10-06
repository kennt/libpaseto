
#ifndef LIBPASERK_H
#define LIBPASERK_H

#ifdef __cplusplus
extern "C"{
#endif

#include "paseto.h"

// key size parameters
#define P384_PUBLICKEYBYTES             48u
#define P384_COMPRESSED_PUBLICKEYBYTES  49u
#define P384_SECRETKEYBYTES             48u


typedef struct
{
    // argon2id parameters
    uint64_t memory;
    uint32_t time;
    uint32_t parallelism;
} v2PasswordParams, v4PasswordParams;

typedef struct
{
    uint32_t iterations;
} v3PasswordParams;

/**
 * Saves the key as a paserk key.
 * Returns a pointer to a NULL-terminated string.
 * The returned string must be freed by paseto_free().
 * NULL is returned on error and errno will be set.
 * 
 * The acceptable values for paserk_id, secret, and opts are:
 * 
 *  paserk_id           secret                  opts
 *  ------------------------------------------------------------
 *  k2.local.           NULL                    NULL
 *  k2.lid.             NULL                    NULL
 *  k2.seal.            Ed25519 pk  (32 bytes)  NULL
 *  k2.local-wrap.pie.  secret key (64 bytes)   NULL
 *  k2.local-pw.        password                v2PasswordParams
 */
char * paseto_v2_local_key_to_paserk(
    uint8_t key[paseto_v2_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts);

/**
 * Extracts the key from the paserk key.
 * true is returned if successful.
 * false is returned on failure/error and errno will be set.
 * 
 * See the previous table for parameter values.
 **/
bool paseto_v2_local_key_from_paserk(
    uint8_t key[paseto_v2_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);



/**
 * Saves the key as a paserk key.
 * Returns a pointer to a NULL-terminated string.
 * The returned string must be freed by paseto_free().
 * NULL is returned on error and errno will be set.
 * 
 * The acceptable values for paserk_id, secret, and opts are:
 * 
 *  paserk_id           secret                  opts
 *  ------------------------------------------------------------
 *  k2.public.           NULL                    NULL
 *  k2.pid.              NULL                    NULL
 */
char * paseto_v2_public_key_to_paserk(
    uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts);

/**
 * Extracts the key from the paserk key.
 * true is returned if successful.
 * false is returned on failure/error and errno will be set.
 * 
 * See the previous table for parameter values.
 **/
bool paseto_v2_public_key_from_paserk(
    uint8_t key[paseto_v2_PUBLIC_PUBLICKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

/**
 * Saves the key as a paserk key.
 * Returns a pointer to a NULL-terminated string.
 * The returned string must be freed by paseto_free().
 * NULL is returned on error and errno will be set.
 * 
 * The acceptable values for paserk_id, secret, and opts are:
 * 
 *  paserk_id           secret                  opts
 *  ------------------------------------------------------------
 *  k2.secret.          NULL                    NULL
 *  k2.sid.             NULL                    NULL
 *  k2.secret-wrap.pie. secret key (64 bytes)   NULL
 *  k2.secret-pw.       password                v2PasswordParams
 */
char * paseto_v2_secret_key_to_paserk(
    uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts);

/**
 * Extracts the key from the paserk key.
 * true is returned if successful.
 * false is returned on failure/error and errno will be set.
 * 
 * See the previous table for parameter values.
 **/
bool paseto_v2_secret_key_from_paserk(
    uint8_t key[paseto_v2_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

uint8_t * paserk_v2_seal_decrypt(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *seckey, size_t seckey_len,
    const uint8_t *data, size_t data_len);

/* this function is also used by v4 */
uint8_t * paserk_v2_seal_encrypt(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *pubkey, size_t pubkey_len,
    const uint8_t *data, size_t data_len);

uint8_t * paserk_v2_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *pubkey, size_t pubkey_len,
    const uint8_t *data, size_t data_len);

uint8_t * paserk_v2_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len);

uint8_t * paserk_v2_password_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len,
    v2PasswordParams *params);

uint8_t * paserk_v2_password_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len);



char * paseto_v3_local_key_to_paserk(
    uint8_t key[paseto_v3_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts);

bool paseto_v3_local_key_from_paserk(
    uint8_t key[paseto_v3_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

char * paseto_v3_public_key_to_paserk(
    uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts);

bool paseto_v3_public_key_from_paserk(
    uint8_t key[paseto_v3_PUBLIC_PUBLICKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

char * paseto_v3_secret_key_to_paserk(
    uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v3PasswordParams *opts);

bool paseto_v3_secret_key_from_paserk(
    uint8_t key[paseto_v3_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

uint8_t * paserk_v3_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *pubkey, size_t pubkey_len,
    const uint8_t *data, size_t data_len);

uint8_t * paserk_v3_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len);



char * paseto_v4_local_key_to_paserk(
    uint8_t key[paseto_v4_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts);

bool paseto_v4_local_key_from_paserk(
    uint8_t key[paseto_v4_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

char * paseto_v4_public_key_to_paserk(
    uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts);

bool paseto_v4_public_key_from_paserk(
    uint8_t key[paseto_v4_PUBLIC_PUBLICKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

char * paseto_v4_secret_key_to_paserk(
    uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v4PasswordParams *opts);

bool paseto_v4_secret_key_from_paserk(
    uint8_t key[paseto_v4_PUBLIC_SECRETKEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len);

#define BIN_TO_BASE64_MAXLEN(len) sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
#define BASE64_TO_BIN_MAXLEN(b64_len) (b64_len / 4 * 3)


#ifdef __cplusplus
};
#endif

#endif /* LIBPASERK_H */

