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
TEST_CASE("paseto_v2local_basic", "[paseto_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    REQUIRE( key->keyType() == paseto::KeyType::V2_LOCAL );
    REQUIRE( key->size() == paseto_v2_LOCAL_KEYBYTES );
    REQUIRE( key->required_length() == paseto_v2_LOCAL_KEYBYTES );
    REQUIRE( key->is_loaded() );

    string data {"test data"};
    paseto::binary_view data_view(data);

    auto encoded_data = key->encrypt(data_view);
    auto token = key->decrypt(encoded_data);

    REQUIRE( token.payload() == data_view );

    // encrypting again should lead to different encrypted data
    {
        auto encoded_data2 = key->encrypt(data_view);
        REQUIRE( encoded_data != encoded_data2 );
    }
}


TEST_CASE("paseto_v2local_unsupported_apis", "[paseto_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    string data {"test data"};

    REQUIRE_THROWS( key->sign(data) );
    REQUIRE_THROWS( key->verify(data) );

    REQUIRE_THROWS( paseto::KeyGen::generatePair(paseto::KeyType::V2_LOCAL) );
}


TEST_CASE("paseto_v2local_implicitassertion", "[paseto_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    string data {"test data"};
    string footer{"footer data"};
    string implicit_assertion{"implicit data"};

    // v2 doesn't support implicit assertions
    REQUIRE_THROWS( key->encrypt(data, footer, implicit_assertion) );
}


TEST_CASE("paseto_v2local_loadFrom", "[paseto_v2local]")
{
    string data {"test data"};

    // Test the various loadFrom calls
    uint8_t binary_data[paseto_v2_LOCAL_KEYBYTES+1];
    randombytes_buf(binary_data, sizeof(binary_data));

    // loadFromBinary
    {
        auto key = paseto::Keys::loadFromBinary(paseto::KeyType::V2_LOCAL,
           paseto::binary_view(binary_data, paseto_v2_LOCAL_KEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v2_LOCAL_KEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V2_LOCAL,
                paseto::binary_view(binary_data, i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromBinary(
                paseto::KeyType::V2_LOCAL,
                paseto::binary_view(binary_data, sizeof(binary_data))) );
    }

    // loadFromHex
    {
        char hex_data[2*sizeof(binary_data)+1];
        save_hex(hex_data, sizeof(hex_data), binary_data, sizeof(binary_data));
        auto key = paseto::Keys::loadFromHex(paseto::KeyType::V2_LOCAL,
                    string_view(hex_data, 2*paseto_v2_LOCAL_KEYBYTES));

        // length-testing
        for (size_t i=0; i<paseto_v2_LOCAL_KEYBYTES; i++)
        {
            REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V2_LOCAL,
                string_view(hex_data, 2*i)) );
        }
        REQUIRE_THROWS( paseto::Keys::loadFromHex(
                paseto::KeyType::V2_LOCAL,
                string_view(hex_data, sizeof(hex_data)-1)) );
    }

    // loadFromBase64
    {
        char base64_data[2*sizeof(binary_data)];
        size_t len = 0;
        REQUIRE( save_base64(base64_data, sizeof(base64_data), &len,
                       binary_data, paseto_v2_LOCAL_KEYBYTES) );
        auto key = paseto::Keys::loadFromBase64(paseto::KeyType::V2_LOCAL,
                    string_view(base64_data, len));

        // try substring
        for (size_t i=0; i<sizeof(binary_data)-1; i++)
        {
            save_base64(base64_data, sizeof(base64_data), &len,
                        binary_data, i);
            REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                                paseto::KeyType::V2_LOCAL,
                                std::string_view(base64_data, len)
                                ));
        }
        // try a too long string
        save_base64(base64_data, sizeof(base64_data), &len,
                    binary_data, sizeof(binary_data));
        REQUIRE_THROWS( paseto::Keys::loadFromBase64(
                            paseto::KeyType::V2_LOCAL,
                            std::string_view(base64_data, len)
                            ));
    }

    // loadFromPem (not supported for v2)
    {
        string pem_secret_key = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----";

        REQUIRE_THROWS( paseto::Keys::loadFromPem(
            paseto::KeyType::V2_LOCAL,
            pem_secret_key) );
    }
}


// V2_LOCAL supports all of the paserk apis
#if 0
TEST_CASE("paseto_v2local_lucidity", "[paseto_v2local]")
{
}
#endif
