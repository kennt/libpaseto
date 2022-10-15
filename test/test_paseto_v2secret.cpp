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
TEST_CASE("paseto_v2secret_basic", "[paseto_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    REQUIRE( secret_key->keyType() == paseto::KeyType::V2_SECRET );
    REQUIRE( secret_key->size() == paseto_v2_PUBLIC_SECRETKEYBYTES );
    REQUIRE( secret_key->required_length() == paseto_v2_PUBLIC_SECRETKEYBYTES );
    REQUIRE( secret_key->is_loaded() );

    string data {"test data"};
    paseto::binary_view data_view(data);
    auto signed_data = secret_key->sign(data_view);

    // check that the verification works
    auto verified_token = public_key->verify(signed_data);
}


TEST_CASE("paseto_v2secret_unsupported_apis", "[paseto_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    string data {"test data"};
    paseto::binary_view data_view(data);
    auto signed_data = secret_key->sign(data_view);

    REQUIRE_THROWS( secret_key->encrypt(data_view) );
    REQUIRE_THROWS( secret_key->decrypt(data) );
    REQUIRE_THROWS( secret_key->verify(signed_data) );

    REQUIRE_THROWS( paseto::KeyGen::generate(paseto::KeyType::V2_SECRET) );
}


TEST_CASE("paseto_v2secret_implicitassertion", "[paseto_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    string data {"test data"};
    string footer {"footer"};
    string implicit_assertion{"implicit data"};
    paseto::binary_view data_view(data);

    // v2 doesn't support implicit assertions
    REQUIRE_THROWS( secret_key->sign(paseto::binary_view {data},
                                     paseto::binary_view {footer},
                                     paseto::binary_view {implicit_assertion}) );
}


TEST_CASE("paseto_v2secret_loadFrom", "[paseto_v2secret]")
{
    string data {"test data"};

    // Test the various loadFrom calls
    uint8_t binary_data[paseto_v2_PUBLIC_SECRETKEYBYTES+1];
    randombytes_buf(binary_data, sizeof(binary_data));

    // loadFromBinary
    {
        auto key = paseto::Keys::loadFromBinary(paseto::KeyType::V2_SECRET,
           paseto::binary_view(binary_data, paseto_v2_PUBLIC_SECRETKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v2_PUBLIC_SECRETKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V2_SECRET,
                paseto::binary_view(binary_data, i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V2_SECRET,
                paseto::binary_view(binary_data, sizeof(binary_data))) );
    }

    // loadFromHex
    {
        char hex_data[2*sizeof(binary_data)+1];
        save_hex(hex_data, sizeof(hex_data), binary_data, sizeof(binary_data));
        auto key = paseto::Keys::loadFromHex(paseto::KeyType::V2_SECRET,
                    string_view(hex_data, 2*paseto_v2_PUBLIC_SECRETKEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v2_PUBLIC_SECRETKEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V2_SECRET,
                string_view(hex_data, 2*i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V2_SECRET,
                string_view(hex_data, sizeof(hex_data)-1)) );
    }

    // loadFromBase64
    {
        char base64_data[2*sizeof(binary_data)];
        size_t len = 0;
        REQUIRE( save_base64(base64_data, sizeof(base64_data), &len,
                       binary_data, paseto_v2_PUBLIC_SECRETKEYBYTES) );
        auto key = paseto::Keys::loadFromBase64(paseto::KeyType::V2_SECRET,
                    string_view(base64_data, len));

        // try substring
        for (size_t i=0; i<sizeof(binary_data)-1; i++)
        {
            save_base64(base64_data, sizeof(base64_data), &len,
                        binary_data, i);
            REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                                paseto::KeyType::V2_SECRET,
                                std::string_view(base64_data, len)
                                ));
        }
        // try a too long string
        save_base64(base64_data, sizeof(base64_data), &len,
                    binary_data, sizeof(binary_data));
        REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                            paseto::KeyType::V2_SECRET,
                            std::string_view(base64_data, len)
                            ));
    }

    // loadFromPem (not supported for v2)
    {
        string pem_private_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----";

        REQUIRE_THROWS( paseto::Keys::loadFromPem(
            paseto::KeyType::V2_SECRET,
            pem_private_key) );
    }
}


// Test unsupported Paserk APIs on V2_SECRET keys
TEST_CASE("paseto_v2secret_lucidity", "[paseto_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    {
        auto sealed_data = local_key->paserkSeal(public_key.get());    
        REQUIRE_THROWS( secret_key->paserkSeal(public_key.get()) );
        REQUIRE_THROWS( secret_key->paserkUnseal(sealed_data, secret_key.get()) );
    }
}
