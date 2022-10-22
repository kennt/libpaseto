extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <string_view>
using std::string_view;

#include <catch2/catch_test_macros.hpp>

static string paserk_public = "k2.public.";
static string paserk_pid = "k2.pid.";

// basic use case
TEST_CASE("paseto_v4public_basic", "[paseto_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    REQUIRE( public_key->keyType() == paseto::KeyType::V4_PUBLIC );
    REQUIRE( public_key->size() == paseto_v4_PUBLIC_PUBLICKEYBYTES );
    REQUIRE( public_key->required_length() == paseto_v4_PUBLIC_PUBLICKEYBYTES );
    REQUIRE( public_key->is_loaded() );

    string data {"test data"};
    auto signed_data = secret_key->sign(data);
    auto verified_token = public_key->verify(signed_data);

    REQUIRE( verified_token.payload().toString() == data );
}


TEST_CASE("paseto_v4public_unsupported_apis", "[paseto_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    string data {"test data"};

    REQUIRE_THROWS( public_key->encrypt(data) );
    REQUIRE_THROWS( public_key->decrypt(data) );
    REQUIRE_THROWS( public_key->sign(data) );

    REQUIRE_THROWS( paseto::KeyGen::generate(paseto::KeyType::V4_PUBLIC) );
}


TEST_CASE("paseto_v4public_implicitassertion", "[paseto_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    string data {"test data"};
    string footer {"footer data"};
    string implicit_assertion{"implicit data"};

    auto signed_data = secret_key->sign(data, footer, implicit_assertion);
    auto token = public_key->verify(signed_data, implicit_assertion);

    REQUIRE( token.payload().toString() == data );
    REQUIRE( token.footer().toString() == footer );

    REQUIRE_THROWS( public_key->verify(signed_data) );
}


TEST_CASE("paseto_v4public_loadFrom", "[paseto_v4public]")
{
    string data {"test data"};

    // Test the various loadFrom calls
    uint8_t binary_data[paseto_v4_PUBLIC_PUBLICKEYBYTES+1];
    randombytes_buf(binary_data, sizeof(binary_data));

    // loadFromBinary
    {
        auto key = paseto::Keys::loadFromBinary(paseto::KeyType::V4_PUBLIC,
           paseto::binary_view(binary_data, paseto_v4_PUBLIC_PUBLICKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v4_PUBLIC_PUBLICKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V4_PUBLIC,
                paseto::binary_view(binary_data, i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V4_PUBLIC,
                paseto::binary_view(binary_data, sizeof(binary_data))) );
    }

    // loadFromHex
    {
        char hex_data[2*sizeof(binary_data)+1];
        save_hex(hex_data, sizeof(hex_data), binary_data, sizeof(binary_data));
        auto key = paseto::Keys::loadFromHex(paseto::KeyType::V4_PUBLIC,
                    string_view(hex_data, 2*paseto_v4_PUBLIC_PUBLICKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v4_PUBLIC_PUBLICKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V4_PUBLIC,
                string_view(hex_data, 2*i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V4_PUBLIC,
                string_view(hex_data, sizeof(hex_data)-1)) );
    }

    // loadFromBase64
    {
        char base64_data[2*sizeof(binary_data)];
        size_t len = 0;
        REQUIRE( save_base64(base64_data, sizeof(base64_data), &len,
                       binary_data, paseto_v4_PUBLIC_PUBLICKEYBYTES) );
        auto key = paseto::Keys::loadFromBase64(paseto::KeyType::V4_PUBLIC,
                    string_view(base64_data, len));

        // try substring
        for (size_t i=0; i<sizeof(binary_data)-1; i++)
        {
            save_base64(base64_data, sizeof(base64_data), &len,
                        binary_data, i);
            REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                                paseto::KeyType::V4_PUBLIC,
                                std::string_view(base64_data, len)
                                ));
        }
        // try a too long string
        save_base64(base64_data, sizeof(base64_data), &len,
                    binary_data, sizeof(binary_data));
        REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                            paseto::KeyType::V4_PUBLIC,
                            std::string_view(base64_data, len)
                            ));
    }

    // loadFromPem (not supported for v4)
    {
        string pem_public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----";
        string pem_secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----";

        REQUIRE_THROWS( paseto::Keys::loadFromPem(
                            paseto::KeyType::V4_PUBLIC,
                            pem_public_key) );
        REQUIRE_THROWS( paseto::Keys::loadFromPem(
                            paseto::KeyType::V4_PUBLIC,
                            pem_public_key) );
    }
}


TEST_CASE("paseto_v4public_lucidity", "[paseto_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    string data {"test data"};

    {
        auto sealed_data = public_key->seal(local_key.get());
        REQUIRE_THROWS( public_key->seal(public_key.get()) );
        REQUIRE_THROWS( public_key->seal(secret_key.get()) );
        REQUIRE_THROWS( secret_key->seal(local_key.get()) );
        REQUIRE_THROWS( secret_key->seal(secret_key.get()) );
        REQUIRE_THROWS( secret_key->seal(public_key.get()) );
        REQUIRE_THROWS( local_key->unseal(sealed_data) );
        REQUIRE_THROWS( public_key->unseal(sealed_data) );
    }

    {
        auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
        auto wrapped_data = wrapping_key->wrap(local_key.get());
        REQUIRE_THROWS( public_key->wrap(local_key.get()) );
        REQUIRE_THROWS( public_key->unwrap(wrapped_data) );
    }

    {
        string password {"password"};
        struct paseto::PasswordParams opts;
            opts.params.v4.time = 1024;
            opts.params.v4.memory = 65536;
            opts.params.v4.parallelism = 1;
        REQUIRE_THROWS( paserk::passwordWrap(public_key.get(), password, &opts) );
    }

    REQUIRE_THROWS( public_key->getPublicKey() );
}
