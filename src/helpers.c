#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include "helpers.h"


static uint8_t *le64(uint8_t *dst, uint64_t i) {
    for (int j = 0; j < 8; ++j) {
        dst[j] = (uint8_t) i;
        i <<= 8;
    }
    return dst + 8;
}


bool pre_auth_init(struct pre_auth *pa, size_t num_elements, size_t sizes) {
    size_t num_bytes = (num_elements + 1) * 8 + sizes;
    pa->base = malloc(num_bytes);
    if (!pa->base) return false;
    pa->current = le64(pa->base, num_elements);
    return true;
}


void pre_auth_append(struct pre_auth *pa, const uint8_t *data, size_t len) {
    pa->current = le64(pa->current, len);
    if (len > 0) memcpy(pa->current, data, len);
    pa->current += len;
}


bool key_load_hex(uint8_t *key, size_t key_len, const char *key_hex) {
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


bool key_load_base64(uint8_t *key, size_t key_len, const char *key_base64) {
    if (!key || !key_base64) {
        errno = EINVAL;
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
        errno = EINVAL;
        return false;
    }
    return true;
}

char * encode_output(size_t *dest_len,
                   const uint8_t *header, size_t header_len,
                   const uint8_t *body, size_t body_len,
                   const uint8_t *footer, size_t footer_len)
{
    size_t output_len = header_len;
    output_len += sodium_base64_ENCODED_LEN(body_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1; // minus included trailing NULL byte
    if (footer) 
        output_len += sodium_base64_ENCODED_LEN(footer_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) - 1 + 1; // minus included NULL byte, plus '.' separator
    output_len += 1; // trailing NULL byte
    char *output = (char *) malloc(output_len);
    if (!output) {
        errno = ENOMEM;
        return NULL;
    }

    char * output_current = output;
    size_t output_len_remaining = output_len;

    if (output_len_remaining < header_len)
    {
        free(output);
        return NULL;
    }
    memcpy(output_current, header, header_len);
    output_current += header_len;
    output_len_remaining -= header_len;

    sodium_bin2base64(
            output_current, output_len_remaining,
            body, body_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    size_t encoded_len = strlen(output_current);
    if (output_len_remaining < encoded_len)
    {
        free(output);
        return NULL;
    }
    output_current += encoded_len;
    output_len_remaining -= encoded_len;

    if (footer && footer_len) {
        *output_current++ = '.';
        output_len_remaining--;
        sodium_bin2base64(
                output_current, output_len_remaining,
                footer, footer_len,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    }
    if (dest_len)
        *dest_len = strlen(output)+1;
    return output;
}


uint8_t * decode_input(
                  const char *encoded, size_t encoded_len,
                  uint8_t **body, size_t *body_len,
                  uint8_t **footer, size_t *footer_len)
{
    size_t decoded_len = encoded_len;
    uint8_t *decoded = (uint8_t *) malloc(decoded_len);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    const char *encoded_footer;
    size_t real_decoded_len;
    if (sodium_base642bin(
            decoded, decoded_len,
            encoded, encoded_len,
            NULL, &real_decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }
    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < real_decoded_len) {
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1 && footer) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        // allocate new memory (need to do this anyway)
        decoded_footer = (uint8_t *) malloc(encoded_footer_len);
        if (decoded_footer == NULL)
        {
            free(decoded);
            errno = ENOMEM;
            return NULL;
        }

        if (sodium_base642bin(
                decoded_footer, encoded_footer_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            free(decoded_footer);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }
    *body = decoded;
    *body_len = real_decoded_len;
    if (footer)
        *footer = decoded_footer;
    if (footer_len)
        *footer_len = decoded_footer_len;
    return decoded;
}

char * format_paserk_key(const char *header, size_t header_len,
                         uint8_t * to_encode, size_t to_encode_len)
{
    if (to_encode == NULL || to_encode_len == 0)
    {
        return NULL;
    }
    // BIN_TO_BASE64_MAXLEN includes a trailing NULL
    size_t paserk_len = header_len + BIN_TO_BASE64_MAXLEN(to_encode_len);
    char *output = malloc(paserk_len);
    if (!output) {
        errno = ENOMEM;
        return NULL;
    }
    char * output_current = output;
    size_t len_remaining = paserk_len;
    memcpy(output_current, header, header_len);

    output_current += header_len;
    len_remaining -= header_len;

    sodium_bin2base64(
            output_current, len_remaining,
            to_encode, to_encode_len,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return output;
}

void _dump_hex(const char * title, const uint8_t *buffer, size_t buffer_len)
{
    fprintf(stdout, "%s (%zu) : ", title, buffer_len);
    for (size_t i=0; i<buffer_len; i++)
        fprintf(stdout, "%02x", buffer[i]);
    fprintf(stdout, "\n");
}
