#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
#include <sodium.h>

#include <string.h>
#include <errno.h>


paseto_static_assert(
        paseto_v2_LOCAL_KEYBYTES == crypto_aead_chacha20poly1305_ietf_KEYBYTES,
        "KEYBYTES mismatch");

paseto_static_assert(
        crypto_pwhash_SALTBYTES == 16,
        "libsodium password hashing is expected to be 16 bytes");


static const uint8_t header[] = "v2.local.";
static const size_t header_len = sizeof(header) - 1;
static const size_t mac_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;


bool paseto_v2_local_load_key_hex(
        uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const char *key_hex) {
    return key_load_hex(key, paseto_v2_LOCAL_KEYBYTES, key_hex);
}


bool paseto_v2_local_load_key_base64(
        uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const char *key_base64) {
    return key_load_base64(key, paseto_v2_LOCAL_KEYBYTES, key_base64);
}


void default_generate_nonce(
        uint8_t nonce[paseto_v2_LOCAL_NONCEBYTES],
        const uint8_t *message, size_t message_len,
        const uint8_t *footer, size_t footer_len) {
    uint8_t nonce_key[paseto_v2_LOCAL_NONCEBYTES];
    randombytes_buf(nonce_key, paseto_v2_LOCAL_NONCEBYTES);
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nonce_key,
            paseto_v2_LOCAL_NONCEBYTES, paseto_v2_LOCAL_NONCEBYTES);
    crypto_generichash_blake2b_update(&state, message, message_len);
    if (footer) {
        crypto_generichash_blake2b_update(&state, footer, footer_len);
    }
    crypto_generichash_blake2b_final(&state, nonce, paseto_v2_LOCAL_NONCEBYTES);

    sodium_memzero(nonce_key, sizeof(nonce_key));
}


generate_nonce_fn generate_nonce = default_generate_nonce;


char *paseto_v2_local_encrypt(
        const uint8_t *message, size_t message_len,
        const uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        const uint8_t *footer, size_t footer_len) {
    if (!message || !key) {
        errno = EINVAL;
        return NULL;
    }
    if (!footer) footer_len = 0;
    if (!footer_len) footer = NULL;

    const size_t ct_len = message_len + mac_len;
    const size_t to_encode_len = paseto_v2_LOCAL_NONCEBYTES + ct_len;
    uint8_t *to_encode = malloc(to_encode_len);
    if (!to_encode) {
        errno = ENOMEM;
        return NULL;
    }

    uint8_t *nonce = to_encode;
    generate_nonce(nonce, message, message_len, footer, footer_len);

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + paseto_v2_LOCAL_NONCEBYTES + footer_len)) {
        sodium_memzero(to_encode, to_encode_len);
        free(to_encode);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, paseto_v2_LOCAL_NONCEBYTES);
    pre_auth_append(&pa, footer, footer_len);
    size_t pre_auth_len = pa.current - pa.base;

    uint8_t *ct = to_encode + paseto_v2_LOCAL_NONCEBYTES;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, NULL,
            message, message_len,
            pa.base, pre_auth_len,
            NULL, nonce, key);

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

uint8_t *paseto_v2_local_decrypt(
        const char *encoded, size_t *output_len,
        const uint8_t key[paseto_v2_LOCAL_KEYBYTES],
        uint8_t **footer, size_t *footer_len) {
    if (!encoded || !output_len || !key) {
        errno = EINVAL;
        return NULL;
    }

    if (strlen(encoded) < header_len + BIN_TO_BASE64_MAXLEN(
                paseto_v2_LOCAL_NONCEBYTES + mac_len) - 1
            || memcmp(encoded, header, header_len) != 0) {
        errno = EINVAL;
        return NULL;
    }

    encoded += header_len;

    const size_t encoded_len = strlen(encoded);
    size_t decoded_len;
    uint8_t *decoded = malloc(encoded_len);
    if (!decoded) {
        errno = ENOMEM;
        return NULL;
    }

    const char *encoded_footer;
    if (sodium_base642bin(
            decoded, encoded_len,
            encoded, encoded_len,
            NULL, &decoded_len,
            &encoded_footer,
            sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        sodium_memzero(decoded, encoded_len);
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    const uint8_t *nonce = decoded;
    // after base64 decoding there should be at least enough data to store the
    // nonce as well as the signature
    if (encoded_len < paseto_v2_LOCAL_NONCEBYTES + mac_len) {
        sodium_memzero(decoded, encoded_len);
        free(decoded);
        errno = EINVAL;
        return NULL;
    }

    size_t encoded_footer_len = strlen(encoded_footer);
    uint8_t *decoded_footer = NULL;
    size_t decoded_footer_len = 0;

    if (encoded_footer_len > 1) {
        // footer present and one or more bytes long
        // skip '.'
        encoded_footer_len--;
        encoded_footer++;

        // use memory after the decoded data for the decoded footer
        decoded_footer = decoded + decoded_len;

        if (sodium_base642bin(
                decoded_footer, encoded_len - decoded_len,
                encoded_footer, encoded_footer_len,
                NULL, &decoded_footer_len,
                NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
            sodium_memzero(decoded, encoded_len);
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }

    struct pre_auth pa;
    if (!pre_auth_init(&pa, 3,
            header_len + paseto_v2_LOCAL_NONCEBYTES + decoded_footer_len)) {
        sodium_memzero(decoded, encoded_len);
        free(decoded);
        errno = ENOMEM;
        return NULL;
    }
    pre_auth_append(&pa, header, header_len);
    pre_auth_append(&pa, nonce, paseto_v2_LOCAL_NONCEBYTES);
    pre_auth_append(&pa, decoded_footer, decoded_footer_len);
    const size_t pre_auth_len = pa.current - pa.base;


    size_t message_len = decoded_len - mac_len + 1;
    uint8_t *message = (uint8_t *) malloc(message_len);
    if (!message) {
        sodium_memzero(decoded, encoded_len);
        sodium_memzero(pa.base, pre_auth_len);
        free(decoded);
        free(pa.base);
        errno = ENOMEM;
        return NULL;
    }
    uint8_t *ct = decoded + paseto_v2_LOCAL_NONCEBYTES;
    const unsigned long long ct_len = decoded_len - paseto_v2_LOCAL_NONCEBYTES;
    unsigned long long internal_message_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            message, &internal_message_len,
            NULL,
            ct, ct_len,
            pa.base, pre_auth_len,
            nonce, key) != 0) {
        sodium_memzero(message, message_len);
        sodium_memzero(decoded, encoded_len);
        sodium_memzero(pa.base, pre_auth_len);
        free(decoded);
        free(pa.base);
        free(message);
        errno = EINVAL;
        return NULL;
    }

    // include a null terminator for convenience
    message[internal_message_len] = '\0';

    sodium_memzero(pa.base, pre_auth_len);
    free(pa.base);

    if (decoded_footer && footer && footer_len) {
        uint8_t *internal_footer = malloc(decoded_footer_len + 1);
        if (!internal_footer) {
            sodium_memzero(decoded, encoded_len);
            sodium_memzero(message, message_len);
            free(decoded);
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

    sodium_memzero(decoded, encoded_len);
    free(decoded);

    *output_len = internal_message_len;

    return message;
}


static const char paserk_local[] = "k2.local.";
static const size_t paserk_local_len = sizeof(paserk_local) - 1;
static const char paserk_lid[] = "k2.lid.";
static const size_t paserk_lid_len = sizeof(paserk_lid) - 1;
static const char paserk_seal[] = "k2.seal.";
static const size_t paserk_seal_len = sizeof(paserk_seal) - 1;
static const char paserk_local_wrap[] = "k2.local-wrap.pie.";
static const size_t paserk_local_wrap_len = sizeof(paserk_local_wrap) - 1;
static const char paserk_local_pw[] = "k2.local-pw.";
static const size_t paserk_local_pw_len = sizeof(paserk_local_pw) - 1;


paseto_static_assert(
        paseto_v2_LOCAL_KEYBYTES == paseto_v4_LOCAL_KEYBYTES,
        "KEYBYTES mismatch");


uint8_t * paserk_v2_seal(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *pubkey, size_t pubkey_len,
    const uint8_t *keydata, size_t keydata_len)
{
    if (!pubkey || !keydata) {
        errno = EINVAL;
        return NULL;
    }

    // v2 and v4 keylengths are the same
    if (keydata_len != paseto_v2_LOCAL_KEYBYTES)
    {
        fprintf(stderr, "unexpected: key lengths must be %u (line %d)\n",
            paseto_v2_LOCAL_KEYBYTES, __LINE__);
        errno = EINVAL;
        return NULL;
    }
    if (pubkey_len != crypto_sign_ed25519_PUBLICKEYBYTES)
    {
        fprintf(stderr, "seal enc key incorrect length: actual:%zu expected:%u (line %d)\n",
            pubkey_len, crypto_sign_ed25519_PUBLICKEYBYTES, __LINE__);
        errno = EINVAL;
        return NULL;
    }

    // #1. Calculate X25519 pubkey (xpk) from Ed25519 pubkey (pk)
    uint8_t xpk[crypto_scalarmult_curve25519_BYTES];
    crypto_sign_ed25519_pk_to_curve25519(xpk, pubkey);

    // #2. Generate ephemeral X25519 key pair (esk, epk)
    uint8_t esk[crypto_sign_SECRETKEYBYTES];
    uint8_t epk[crypto_sign_PUBLICKEYBYTES];

    // generate an Ed25519 keypair
    // From that generate the Curve25519 keypair
    uint8_t t_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
    uint8_t t_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    crypto_sign_ed25519_keypair(t_pk, t_skpk);
    crypto_sign_ed25519_pk_to_curve25519(epk, t_pk);
    crypto_sign_ed25519_sk_to_curve25519(esk, t_skpk);

    // #3. Calculate the shared secret xk
    uint8_t xk[crypto_scalarmult_BYTES];
    crypto_scalarmult(xk, esk, xpk);

    sodium_memzero(esk, sizeof(esk));
    sodium_memzero(t_skpk, sizeof(t_skpk));
    sodium_memzero(t_pk, sizeof(t_pk));


    // #4. Calculate the encryption key Ek
    size_t encode_len = 1 + header_len +
                        sizeof(xk) + sizeof(epk) + sizeof(xpk);
    uint8_t * encode_buffer = (uint8_t *) malloc(encode_len);
    if (!encode_buffer) {
        errno = ENOMEM;
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(epk, sizeof(epk));
        sodium_memzero(xk, sizeof(xk));
        return NULL;
    }

    encode_buffer[0] = 0x01;
    memcpy(encode_buffer + 1, header, header_len);
    memcpy(encode_buffer + 1 + header_len, xk, sizeof(xk));
    memcpy(encode_buffer + 1 + header_len + sizeof(xk), epk, sizeof(epk));
    memcpy(encode_buffer + 1 + header_len + sizeof(xk) + sizeof(epk), xpk, sizeof(xpk));

    uint8_t Ek[32];
    crypto_generichash(Ek, sizeof(Ek), encode_buffer, encode_len, NULL, 0);

    // #5. Calculate the authentication key (Ak)
    uint8_t Ak[32];
    encode_buffer[0] = 0x02;
    crypto_generichash(Ak, sizeof(Ak), encode_buffer, encode_len, NULL, 0);

    // #6. Calculate the nonce
    // reuse the encode-buffer
    uint8_t nonce[24];
    crypto_generichash(nonce, sizeof(nonce),
        encode_buffer + 1 + header_len + sizeof(xk),
        sizeof(epk) + sizeof(xpk),
        NULL, 0);

    sodium_memzero(encode_buffer, encode_len);
    free(encode_buffer);

    // #7. Encrypt pdk, result is edk (encrypted data key)
    size_t edk_len = keydata_len;
    uint8_t edk[paseto_v2_LOCAL_KEYBYTES];
    crypto_stream_xchacha20_xor(
        edk,
        keydata, keydata_len,
        nonce, Ek);

    // #8. Calculate the auth tag
    uint8_t tag[32];
    size_t new_output_len = sizeof(tag) + sizeof(epk) + edk_len;
    uint8_t * output = (uint8_t *) malloc(new_output_len);
    if (!output) {
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(epk, sizeof(epk));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(edk, sizeof(edk));
        errno = ENOMEM;
        return NULL;
    }
    memcpy(output, header, header_len);
    memcpy(output + header_len, epk, sizeof(epk));
    memcpy(output + header_len + sizeof(epk), edk, edk_len);

    crypto_generichash(tag, sizeof(tag),
        output, header_len + sizeof(epk) + edk_len,
        Ak, sizeof(Ak));

    // #9. Return t || epk || edk
    memcpy(output, tag, sizeof(tag));
    memcpy(output + sizeof(tag), epk, sizeof(epk));
    memcpy(output + sizeof(tag) + sizeof(epk), edk, edk_len);

    if (output_len)
        *output_len = new_output_len;

    sodium_memzero(xpk, sizeof(xpk));
    sodium_memzero(epk, sizeof(epk));
    sodium_memzero(xk, sizeof(xk));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(edk, sizeof(edk));
    sodium_memzero(tag, sizeof(tag));
    return output;
}


uint8_t * paserk_v2_unseal(size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *seckey, size_t seckey_len,
    const uint8_t *data, size_t data_len)
{
    if (!seckey || !data) {
        errno = EINVAL;
        return NULL;
    }

    if (data_len != (32 + crypto_sign_PUBLICKEYBYTES + paseto_v2_LOCAL_KEYBYTES))
    {
        fprintf(stderr, "seal encrypted data incorrect length: actual:%zu  expected:%d\n",
            data_len, 32 + crypto_sign_PUBLICKEYBYTES + paseto_v2_LOCAL_KEYBYTES);
        errno = EINVAL;
        return NULL;
    }

    // Break the data into parts
    size_t tag_len = 32;
    size_t epk_len = crypto_sign_PUBLICKEYBYTES;
    size_t edk_len = data_len - tag_len - epk_len;

    // TODO: check there is enough data

    const uint8_t * tag = data;
    const uint8_t * epk = data + tag_len;
    const uint8_t * edk = data + tag_len + epk_len;

    // #1. Verify header and secret key

    // #2. Calculate x25519 secret key from sk (xsk)
    uint8_t xsk[crypto_scalarmult_curve25519_BYTES];
    uint8_t xpk[crypto_sign_PUBLICKEYBYTES];
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_sk_to_curve25519(xsk, seckey);
    crypto_sign_ed25519_sk_to_pk(pk, seckey);
    crypto_sign_ed25519_pk_to_curve25519(xpk, pk);

    // #3. Calculate shared secret xk
    uint8_t xk[crypto_scalarmult_BYTES];
    crypto_scalarmult(xk, xsk, epk);

    sodium_memzero(xsk, sizeof(xsk));
    sodium_memzero(pk, sizeof(pk));

    // #4. Calculate authentication key
    uint8_t Ak[32];
    size_t encode_len = 1 + header_len +
                        sizeof(xk) + epk_len + sizeof(xpk);
    uint8_t * encode_buffer = (uint8_t *) malloc(encode_len);
    if (!encode_buffer) {
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(xk, sizeof(xk));
        errno = ENOMEM;
        return NULL;
    }

    encode_buffer[0] = 0x02;
    memcpy(encode_buffer + 1, header, header_len);
    memcpy(encode_buffer + 1 + header_len, xk, sizeof(xk));
    memcpy(encode_buffer + 1 + header_len + sizeof(xk), epk, epk_len);
    memcpy(encode_buffer + 1 + header_len + sizeof(xk) + epk_len, xpk, sizeof(xpk));

    crypto_generichash(Ak, sizeof(Ak), encode_buffer, encode_len, NULL, 0);

    // #5. Recalculate the auth tag (tag2)
    uint8_t tag2[32];
    size_t auth_buffer_len = header_len + epk_len + edk_len;
    uint8_t * auth_buffer = (uint8_t *) malloc(auth_buffer_len);
    if (!auth_buffer) {
        sodium_memzero(encode_buffer, encode_len);
        free(encode_buffer);
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(Ak, sizeof(Ak));
        errno = ENOMEM;
        return NULL;
    }
    memcpy(auth_buffer, header, header_len);
    memcpy(auth_buffer + header_len, epk, epk_len);
    memcpy(auth_buffer + header_len + epk_len, edk, edk_len);

    crypto_generichash(tag2, sizeof(tag2), auth_buffer, auth_buffer_len, Ak, sizeof(Ak));
    free(auth_buffer);

    // #6. Compare tag and tag2.  Reject if different
    if (sodium_memcmp(tag, tag2, sizeof(tag2)) != 0)
    {
        sodium_memzero(encode_buffer, encode_len);
        free(encode_buffer);
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag2, sizeof(tag2));
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(tag2, sizeof(tag2));

    // #7. Calculate the encryption key (Ek)
    uint8_t Ek[32];
    encode_buffer[0] = 0x01;
    crypto_generichash(Ek, sizeof(Ek), encode_buffer, encode_len, NULL, 0);

    // #8. Calculate the nonce
    // reuse the encode-buffer
    uint8_t nonce[24];
    memcpy(encode_buffer, epk, epk_len);
    memcpy(encode_buffer + epk_len, xpk, sizeof(xpk));
    crypto_generichash(nonce, sizeof(nonce),
        encode_buffer, epk_len + sizeof(xpk),
        NULL, 0);
    sodium_memzero(encode_buffer, encode_len);
    free(encode_buffer);

    // #9. Decrypt edk with Ek and nonce
    uint8_t * output = (uint8_t *) malloc(edk_len);
    if (!output) {
        sodium_memzero(xpk, sizeof(xpk));
        sodium_memzero(xk, sizeof(xk));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce, sizeof(nonce));
        errno = ENOMEM;
        return NULL;
    }
    crypto_stream_xchacha20_xor(
        output,
        edk, edk_len,
        nonce, Ek);

    // 10. Return the plaintext data key (pdk)
    if (output_len)
        *output_len = edk_len;

    sodium_memzero(xpk, sizeof(xpk));
    sodium_memzero(xk, sizeof(xk));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(nonce, sizeof(nonce));
    return output;
}

uint8_t * paserk_v2_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len)
{
    if (!wrapkey || !data) {
        errno = EINVAL;
        return NULL;
    }

    // #1. Enforce algorithm lucidity
    // #2. Generate a randam nonce
    uint8_t nonce[32];
    randombytes_buf(nonce, sizeof(nonce));

    // #3. Derive encryption key (Ek) and nonce2
    uint8_t Ek[32];
    uint8_t nonce2[24];
    {
        uint8_t digest[56];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x80;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        crypto_generichash(digest, sizeof(digest),
            to_hash, sizeof(to_hash),
            wrapkey, wrapkey_len);

        memcpy(Ek, digest, sizeof(Ek));
        memcpy(nonce2, digest+sizeof(Ek), sizeof(nonce2));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #4. Derive authentication key (Ak)
    uint8_t Ak[32];
    {
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x81;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        crypto_generichash(Ak, sizeof(Ak),
            to_hash, sizeof(to_hash),
            wrapkey, wrapkey_len);
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #5. Encrypt plaintext key (data) as ciphertext
    size_t ciphertext_len = data_len;
    uint8_t * ciphertext = (uint8_t *) malloc(ciphertext_len);
    if (!ciphertext)
    {
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce2, sizeof(nonce2));
        sodium_memzero(Ak, sizeof(Ak));
        errno = ENOMEM;
        return NULL;
    }
    crypto_stream_xchacha20_xor(
        ciphertext,
        data, data_len,
        nonce2, Ek);

    // #6. Calculate authentication tag (tag)
    uint8_t tag[32];
    {
        uint8_t to_hash[header_len + sizeof(nonce) + ciphertext_len];
        memcpy(to_hash, header, header_len);
        memcpy(to_hash + header_len, nonce, sizeof(nonce));
        memcpy(to_hash + header_len + sizeof(nonce), ciphertext, ciphertext_len);
        crypto_generichash(tag, sizeof(tag),
            to_hash, sizeof(to_hash),
            Ak, sizeof(Ak));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #7. Return tag || nonce || ciphertext
    size_t out_len = sizeof(tag) + sizeof(nonce) + ciphertext_len;
    uint8_t * out = (uint8_t *) malloc(out_len);
    if (!out) {
        sodium_memzero(ciphertext, ciphertext_len);
        free(ciphertext);
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce2, sizeof(nonce2));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag, sizeof(tag));
        errno = ENOMEM;
        return NULL;
    }
    memcpy(out, tag, sizeof(tag));
    memcpy(out + sizeof(tag), nonce, sizeof(nonce));
    memcpy(out + sizeof(tag) + sizeof(nonce), ciphertext, ciphertext_len);

    sodium_memzero(ciphertext, ciphertext_len);
    free(ciphertext);
    if (output_len)
        *output_len = out_len;

    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(nonce2, sizeof(nonce2));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(tag, sizeof(tag));
    return out;
}

uint8_t * paserk_v2_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *wrapkey, size_t wrapkey_len,
    const uint8_t *data, size_t data_len)
{
    if (!wrapkey || !data) {
        errno = EINVAL;
        return NULL;
    }

    // #1. Decode base64, break apart into tag, nonce, and cipherkey
    uint8_t tag[32];
    uint8_t nonce[32];

    if (data_len <= (sizeof(tag) + sizeof(nonce)))
    {
        fprintf(stderr, "encrypted data too short: actual:%zu <= expected:%zu\n",
            data_len, sizeof(tag) + sizeof(nonce));
        errno = EINVAL;
        return NULL;
    }

    size_t ciphertext_len = data_len - sizeof(tag) - sizeof(nonce);
    uint8_t * ciphertext = (uint8_t *) malloc(ciphertext_len);
    if (!ciphertext) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(tag, data, sizeof(tag));
    memcpy(nonce, data+sizeof(tag), sizeof(nonce));
    memcpy(ciphertext, data + sizeof(tag) + sizeof(nonce), ciphertext_len);

    // #2. Derive auth key
    uint8_t Ak[32];
    {
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x81;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        crypto_generichash(Ak, sizeof(Ak),
            to_hash, sizeof(to_hash),
            wrapkey, wrapkey_len);

        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #3. Recalculate auth tag
    uint8_t tag2[32];
    {
        uint8_t to_hash[header_len + sizeof(nonce) + ciphertext_len];
        memcpy(to_hash, header, header_len);
        memcpy(to_hash + header_len, nonce, sizeof(nonce));
        memcpy(to_hash + header_len + sizeof(nonce), ciphertext, ciphertext_len);
        crypto_generichash(tag2, sizeof(tag2),
            to_hash, sizeof(to_hash),
            Ak, sizeof(Ak));

        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #4. Compare tags
    if (sodium_memcmp(tag, tag2, sizeof(tag)) != 0)
    {
        sodium_memzero(ciphertext, ciphertext_len);
        free(ciphertext);
        sodium_memzero(tag, sizeof(tag));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag2, sizeof(tag2));
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(tag2, sizeof(tag2));

    // #5. Derive encryption key and nonce3
    uint8_t Ek[32];
    uint8_t nonce2[24];
    {
        uint8_t digest[56];
        uint8_t to_hash[1 + sizeof(nonce)];
        to_hash[0] = 0x80;
        memcpy(to_hash+1, nonce, sizeof(nonce));
        crypto_generichash(digest, sizeof(digest),
            to_hash, sizeof(to_hash),
            wrapkey, wrapkey_len);

        memcpy(Ek, digest, sizeof(Ek));
        memcpy(nonce2, digest+sizeof(Ek), sizeof(nonce2));

        sodium_memzero(digest, sizeof(digest));
        sodium_memzero(to_hash, sizeof(to_hash));
    }

    // #6. Decrypt cipherkey
    size_t plaintext_len = ciphertext_len;
    uint8_t * plaintext = (uint8_t *) malloc(plaintext_len);
    if (!plaintext)
    {
        sodium_memzero(ciphertext, ciphertext_len);
        free(ciphertext);
        sodium_memzero(tag, sizeof(tag));
        sodium_memzero(nonce, sizeof(nonce));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(nonce2, sizeof(nonce2));
        errno = ENOMEM;
        return NULL;
    }
    crypto_stream_xchacha20_xor(
        plaintext,
        ciphertext, ciphertext_len,
        nonce2, Ek);

    sodium_memzero(ciphertext, ciphertext_len);
    free(ciphertext);

    // #7. Algorithm lucidity
    // #8. Return plaintext
    if (output_len)
        *output_len = plaintext_len;

    sodium_memzero(tag, sizeof(tag));
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(nonce2, sizeof(nonce2));
    return plaintext;
}

uint8_t * paserk_v2_password_wrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len,
    v2PasswordParams *params)
{
    if (!params || !password || !data) {
        errno = EINVAL;
        return NULL;
    }

    // #1. Generate a random 16-byte salt (s)
    uint8_t salt[16];
    randombytes_buf(salt, sizeof(salt));

    // #2. Derive pre-key k from the password and salt (k)
    uint8_t k[32];
    if (crypto_pwhash(k, sizeof(k),
            (const char *)password, password_len,
            salt,
            params->time, params->memory,
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        sodium_memzero(salt, sizeof(salt));
        errno = EINVAL;
        return NULL;
    }

    // #3. Derive encryption key (Ek)
    // #4. Derive the authentication key (Ak)
    uint8_t Ek[32];
    uint8_t Ak[32];
    {
        uint8_t buffer[1 + sizeof(k)];
        buffer[0] = 0xFF;
        memcpy(buffer + 1, k, sizeof(k));
        crypto_generichash(Ek, sizeof(Ek), buffer, sizeof(buffer), NULL, 0);

        buffer[0] = 0xFE;
        crypto_generichash(Ak, sizeof(Ak), buffer, sizeof(buffer), NULL, 0);

        sodium_memzero(buffer, sizeof(buffer));
    }

    // #5. Generate random 24-byte nonce (n)
    uint8_t nonce[24];
    randombytes_buf(nonce, sizeof(nonce));

    // #6. Encrypt plaintext key (ptk) to get encrypted data key (edk)
    size_t edk_len = data_len;
    uint8_t * edk = (uint8_t *) malloc(edk_len);
    if (!edk) {
        sodium_memzero(salt, sizeof(salt));
        sodium_memzero(k, sizeof(k));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(nonce, sizeof(nonce));
        errno = ENOMEM;
        return NULL;
    }
    crypto_stream_xchacha20_xor(
        edk,
        data, data_len,
        nonce, Ek);

    // #7. Calculate the authentication tag (tag)
    // #8. Return the result
    size_t buffer_len = header_len
                        + sizeof(salt)
                        + sizeof(uint64_t)      // mem
                        + sizeof(uint32_t)      // time
                        + sizeof(uint32_t)      // para
                        + sizeof(nonce)
                        + edk_len
                        + 32;                   // sizeof(tag)
    uint8_t * buffer = (uint8_t *) malloc(buffer_len);
    if (!buffer) {
        sodium_memzero(edk, edk_len);
        free(edk);
        sodium_memzero(salt, sizeof(salt));
        sodium_memzero(k, sizeof(k));
        sodium_memzero(Ek, sizeof(Ek));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(nonce, sizeof(nonce));
        errno = ENOMEM;
        return NULL;
    }
    {
        uint8_t * current = buffer;
        memcpy(current, header, header_len);
        current += header_len;

        memcpy(current, salt, sizeof(salt));
        current += sizeof(salt);

        current = WRITE64BE(current, params->memory);
        current = WRITE32BE(current, params->time);
        current = WRITE32BE(current, params->parallelism);

        memcpy(current, nonce, sizeof(nonce));
        current += sizeof(nonce);

        memcpy(current, edk, edk_len);
        current += edk_len;

        // This will place the tag at the end of the
        // buffer, so that it's ready for output
        crypto_generichash(current, 32,
                buffer, current - buffer,
                Ak, sizeof(Ak));
    }
    sodium_memzero(edk, edk_len);
    free(edk);

    // Now move the buffer down (we do not want to return the header)
    memmove(buffer, buffer + header_len, buffer_len - header_len);

    if (output_len)
        *output_len = buffer_len - header_len;

    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(k, sizeof(k));
    sodium_memzero(Ek, sizeof(Ek));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(nonce, sizeof(nonce));
    return buffer;
}


uint8_t * paserk_v2_password_unwrap(
    size_t *output_len,
    const char * header, size_t header_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *data, size_t data_len)
{
    if (!password || !data)
    {
        errno = EINVAL;
        return NULL;
    }

    v2PasswordParams params;
    size_t salt_len = 16;
    size_t nonce_len = 24;
    size_t tag_len = 32;

    const uint8_t * current = data;
    const uint8_t * salt = current;
    current += salt_len;
    current += sizeof(uint64_t);    // mem
    current += sizeof(uint32_t);    // time
    current += sizeof(uint32_t);    // para
    const uint8_t * nonce = current;
    current += nonce_len;
    const uint8_t * ciphertext = current;

    if (data_len <= (salt_len + sizeof(uint64_t) + 2*sizeof(uint32_t) + nonce_len))
    {
        fprintf(stderr, "encrypted data too short: actual:%zu <= expected:%zu\n",
            data_len, salt_len + sizeof(uint64_t) + 2*sizeof(uint32_t) + nonce_len);
        errno = EINVAL;
        return NULL;
    }

    size_t ciphertext_len = data_len - (current - data) - tag_len;
    current += ciphertext_len;
    const uint8_t * tag = current;

    // Read in the params structure
    {
        const uint8_t * p = salt + salt_len;
        params.memory = READ64BE(p);
        p += sizeof(uint64_t);
        //params.memory /= 1024u;

        params.time = READ32BE(p);
        p += sizeof(uint32_t);

        params.parallelism = READ32BE(p);
    }

    // #1. Algorithm lucidity
    // #2. Derive pre-key k
    uint8_t prekey[32];
    if (crypto_pwhash(prekey, sizeof(prekey),
            (const char *) password, password_len,
            salt,
            params.time, params.memory,
            crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        errno = EINVAL;
        return NULL;
    }

    // #3. Recalculate the auth key (Ak)
    uint8_t Ak[32];
    {
        uint8_t buffer[1 + sizeof(prekey)];
        buffer[0] = 0xFE;
        memcpy(buffer + 1, prekey, sizeof(prekey));
        crypto_generichash(Ak, sizeof(Ak), buffer, sizeof(buffer), NULL, 0);

        sodium_memzero(buffer, sizeof(buffer));
    }

    // #4. Recalculate the tag (t2)
    uint8_t tag2[32];
    {
        uint8_t * buffer = (uint8_t *) malloc(data_len + header_len - tag_len);
        if (!buffer) {
            errno = ENOMEM;
            sodium_memzero(prekey, sizeof(prekey));
            sodium_memzero(Ak, sizeof(Ak));
            return NULL;
        }
        memcpy(buffer, header, header_len);
        memcpy(buffer + header_len, data, data_len - tag_len);
        crypto_generichash(tag2, sizeof(tag2), buffer, header_len + data_len - tag_len, Ak, sizeof(Ak));

        sodium_memzero(buffer, data_len + header_len - tag_len);        
        free(buffer);
    }

    // #5. Compare t2 with the oriinal tag
    if (sodium_memcmp(tag, tag2, sizeof(tag2)) != 0)
    {
        sodium_memzero(prekey, sizeof(prekey));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(tag2, sizeof(tag2));
        errno = EINVAL;
        return NULL;
    }
    sodium_memzero(tag2, sizeof(tag2));

    // #6. Derive the encryption key (Ek)
    uint8_t Ek[32];
    {
        uint8_t buffer[1 + sizeof(prekey)];
        buffer[0] = 0xFF;
        memcpy(buffer + 1, prekey, sizeof(prekey));
        crypto_generichash(Ek, sizeof(Ek), buffer, sizeof(buffer), NULL, 0);

        sodium_memzero(buffer, sizeof(buffer));
    }

    // #7. Decrypt the encrypted data key (edk)
    size_t plaintext_len = ciphertext_len;
    uint8_t * plaintext = (uint8_t *) malloc(plaintext_len);
    if (!plaintext) {
        sodium_memzero(prekey, sizeof(prekey));
        sodium_memzero(Ak, sizeof(Ak));
        sodium_memzero(Ek, sizeof(Ek));
        errno = ENOMEM;
        return NULL;
    }
    crypto_stream_xchacha20_xor(
        plaintext,
        ciphertext, ciphertext_len,
        nonce, Ek);

    // #8. Return the plaintext key (ptk)
    if (output_len)
        *output_len = plaintext_len;

    sodium_memzero(prekey, sizeof(prekey));
    sodium_memzero(Ak, sizeof(Ak));
    sodium_memzero(Ek, sizeof(Ek));
    return plaintext;
}


char * paseto_v2_local_key_to_paserk(
    uint8_t key[paseto_v2_LOCAL_KEYBYTES],
    const char *paserk_id,
    const uint8_t * secret, size_t secret_len,
    v2PasswordParams *opts)
{
    if (!paserk_id)
    {
        errno = EINVAL;
        return NULL;
    }

    if (strncmp(paserk_id, paserk_local, paserk_local_len) == 0)
    {
        return format_paserk_key(paserk_local, paserk_local_len,
                                 key, paseto_v2_LOCAL_KEYBYTES);
    }
    else if (strncmp(paserk_id, paserk_lid, paserk_lid_len) == 0)
    {
        char * paserk_key = paseto_v2_local_key_to_paserk(key, paserk_local, NULL, 0, NULL);

        size_t to_encode_len = paserk_lid_len + strlen(paserk_key);
        uint8_t * to_encode = (uint8_t *)malloc(to_encode_len + 1);
        if (!to_encode) {
            free(paserk_key);
            errno = ENOMEM;
            return NULL;
        }
        memcpy(to_encode, paserk_lid, paserk_lid_len);
        memcpy(to_encode+paserk_lid_len, paserk_key, to_encode_len - paserk_lid_len);

        uint8_t hash[33];
        crypto_generichash(hash, sizeof(hash), to_encode, to_encode_len, NULL, 0);

        free(to_encode);
        free(paserk_key);

        return format_paserk_key(paserk_lid, paserk_lid_len,
                                 hash, sizeof(hash));
    }
    else if (strncmp(paserk_id, paserk_seal, paserk_seal_len) == 0)
    {
        size_t encoded_len = 0;
        uint8_t * encoded = paserk_v2_seal(&encoded_len,
            paserk_seal, paserk_seal_len,
            secret, secret_len,
            key, paseto_v2_LOCAL_KEYBYTES);

        char * output = format_paserk_key(paserk_seal, paserk_seal_len,
                                          encoded, encoded_len);
        free(encoded);
        return output;
    }
    else if (strncmp(paserk_id, paserk_local_wrap, paserk_local_wrap_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_wrap(
                    &out_len,
                    paserk_local_wrap, paserk_local_wrap_len,
                    secret, secret_len,
                    key, paseto_v2_LOCAL_KEYBYTES);
        char * output = format_paserk_key(paserk_local_wrap, paserk_local_wrap_len,
                                out, out_len);
        free(out);
        return output;
    }
    else if (strncmp(paserk_id, paserk_local_pw, paserk_local_pw_len) == 0)
    {
        size_t out_len;
        uint8_t * out = paserk_v2_password_wrap(
                    &out_len,
                    paserk_local_pw, paserk_local_pw_len,
                    secret, secret_len,
                    key, paseto_v2_LOCAL_KEYBYTES,
                    opts);
        char * output = format_paserk_key(paserk_local_pw, paserk_local_pw_len,
                                out, out_len);
        free(out);
        return output;
    }
    errno = EINVAL;
    return NULL;
}


bool paseto_v2_local_key_from_paserk(
    uint8_t key[paseto_v2_LOCAL_KEYBYTES],
    const char * paserk_key, size_t paserk_key_len,
    const uint8_t * secret, size_t secret_len)
{
    if (strncmp(paserk_key, paserk_local, paserk_local_len) == 0)
    {
        size_t len;
        if (sodium_base642bin(
                key, paseto_v2_LOCAL_KEYBYTES,
                paserk_key + paserk_local_len, paserk_key_len - paserk_local_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0)
        {
            return true;
        }
    }
    else if (strncmp(paserk_key, paserk_seal, paserk_seal_len) == 0)
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
                paserk_key + paserk_seal_len, paserk_key_len - paserk_seal_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_unseal(&output_len,
                        paserk_seal, paserk_seal_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v2_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unexpected key length: actual:%zu expected:%u\n",
                output_len, paseto_v2_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v2_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    else if (strncmp(paserk_key, paserk_local_wrap, paserk_local_wrap_len) == 0)
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
                paserk_key + paserk_local_wrap_len, paserk_key_len - paserk_local_wrap_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_unwrap(
                        &output_len,
                        paserk_local_wrap, paserk_local_wrap_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v2_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unwrapped key length mismatch: actual:%zu expected:%u\n",
                output_len, paseto_v2_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v2_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    else if (strncmp(paserk_key, paserk_local_pw, paserk_local_pw_len) == 0)
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
                paserk_key + paserk_local_pw_len, paserk_key_len - paserk_local_pw_len,
                NULL, &len, NULL,
                sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        {
            free(paserk_data);
            return false;
        }

        size_t output_len;
        uint8_t * pdk = paserk_v2_password_unwrap(
                        &output_len,
                        paserk_local_pw, paserk_local_pw_len,
                        secret, secret_len,
                        paserk_data, len);
        if (!pdk) {
            free(paserk_data);
            return false;
        }
        free(paserk_data);

        if (output_len != paseto_v2_LOCAL_KEYBYTES)
        {
            fprintf(stderr, "unwrapped key length mismatch: actual:%zu expected:%u\n",
                output_len, paseto_v2_LOCAL_KEYBYTES);
            free(pdk);
            errno = EINVAL;
            return false;
        }
        memcpy(key, pdk, paseto_v2_LOCAL_KEYBYTES);

        free(pdk);
        return true;
    }
    errno = EINVAL;
    return false;
}
