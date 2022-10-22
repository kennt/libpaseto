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


// basic use case
TEST_CASE("paseto_v3secret_basic", "[paseto_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    REQUIRE( secret_key->keyType() == paseto::KeyType::V3_SECRET );
    REQUIRE( secret_key->size() == paseto_v3_PUBLIC_SECRETKEYBYTES );
    REQUIRE( secret_key->required_length() == paseto_v3_PUBLIC_SECRETKEYBYTES );
    REQUIRE( secret_key->is_loaded() );

    string data {"test data"};
    auto signed_data = secret_key->sign(data);

    // check that the verification works
    auto verified_token = public_key->verify(signed_data);
}


TEST_CASE("paseto_v3secret_unsupported_apis", "[paseto_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string data {"test data"};
    auto signed_data = secret_key->sign(data);

    REQUIRE_THROWS( secret_key->encrypt(data) );
    REQUIRE_THROWS( secret_key->decrypt(data) );
    REQUIRE_THROWS( secret_key->verify(signed_data) );

    REQUIRE_THROWS( paseto::KeyGen::generate(paseto::KeyType::V3_SECRET) );
}


TEST_CASE("paseto_v3secret_implicitassertion", "[paseto_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string data {"test data"};
    string footer {"footer"};
    string implicit_assertion{"implicit data"};

    auto signed_data = secret_key->sign(data, footer, implicit_assertion);
    auto token = public_key->verify(signed_data, implicit_assertion);

    REQUIRE( token.payload().toString() == data );
    REQUIRE( token.footer().toString() == footer );
}


TEST_CASE("paseto_v3secret_loadFrom", "[paseto_v3secret]")
{
    string data {"test data"};

    // Test the various loadFrom calls
    uint8_t binary_data[paseto_v3_PUBLIC_SECRETKEYBYTES+1];
    randombytes_buf(binary_data, sizeof(binary_data));

    // loadFromBinary
    {
        auto key = paseto::Keys::loadFromBinary(paseto::KeyType::V3_SECRET,
           paseto::binary_view(binary_data, paseto_v3_PUBLIC_SECRETKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v3_PUBLIC_SECRETKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V3_SECRET,
                paseto::binary_view(binary_data, i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V3_SECRET,
                paseto::binary_view(binary_data, sizeof(binary_data))) );
    }

    // loadFromHex
    {
        char hex_data[2*sizeof(binary_data)+1];
        save_hex(hex_data, sizeof(hex_data), binary_data, sizeof(binary_data));
        auto key = paseto::Keys::loadFromHex(paseto::KeyType::V3_SECRET,
                    string_view(hex_data, 2*paseto_v3_PUBLIC_SECRETKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v3_PUBLIC_SECRETKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V3_SECRET,
                string_view(hex_data, 2*i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V3_SECRET,
                string_view(hex_data, sizeof(hex_data)-1)) );
    }

    // loadFromBase64
    {
        char base64_data[2*sizeof(binary_data)];
        size_t len = 0;
        REQUIRE( save_base64(base64_data, sizeof(base64_data), &len,
                       binary_data, paseto_v3_PUBLIC_SECRETKEYBYTES) );
        auto key = paseto::Keys::loadFromBase64(paseto::KeyType::V3_SECRET,
                    string_view(base64_data, len));

        // try substring
        for (size_t i=0; i<sizeof(binary_data)-1; i++)
        {
            save_base64(base64_data, sizeof(base64_data), &len,
                        binary_data, i);
            REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                                paseto::KeyType::V3_SECRET,
                                std::string_view(base64_data, len)
                                ));
        }
        // try a too long string
        save_base64(base64_data, sizeof(base64_data), &len,
                    binary_data, sizeof(binary_data));
        REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                            paseto::KeyType::V3_SECRET,
                            std::string_view(base64_data, len)
                            ));
    }

    // loadFromPem (not supported for v3)
    {
        string pem_public_key = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----";
        string pem_secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----";

        REQUIRE_THROWS( paseto::Keys::loadFromPem(
                            paseto::KeyType::V3_SECRET,
                            pem_public_key) );

        auto pem_key = paseto::Keys::loadFromPem(
                            paseto::KeyType::V3_SECRET,
                            pem_secret_key);
    }
}


// Test unsupported Paserk APIs on V3_SECRET keys
TEST_CASE("paseto_v3secret_lucidity", "[paseto_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);

    {
        auto sealed_data = public_key->seal(local_key.get());
        REQUIRE_THROWS( public_key->seal(secret_key.get()) );
        REQUIRE_THROWS( local_key->unseal(sealed_data) );
    }
}


TEST_CASE("paseto_v3secret_getPublicKey", "[paseto_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    auto key = secret_key->getPublicKey();

    REQUIRE( key->keyType() == paseto::KeyType::V3_PUBLIC );
    REQUIRE( *key == *public_key );
}
