extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>

std::string paserk_local = "k2.local.";
std::string paserk_lid = "k2.lid.";
std::string paserk_seal = "k2.seal.";


TEST_CASE("paseto_v2local", "[v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    REQUIRE( key->keyType() == paseto::KeyType::V2_LOCAL );
    REQUIRE( key->size() == paseto_v2_LOCAL_KEYBYTES );
    REQUIRE( key->required_length() == paseto_v2_LOCAL_KEYBYTES );
    REQUIRE( key->is_loaded() );

    std::string data {"test data"};
    paseto::binary_view data_view(data);

    auto encoded_data = key->encrypt(data_view);
    auto token = key->decrypt(encoded_data);

    REQUIRE( token.payload() == data_view );
}

TEST_CASE("paseto_v2local_unsupported_apis", "[v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    std::string data {"test data"};

    REQUIRE_THROWS(
        key->sign(data)
    );

    REQUIRE_THROWS(
        key->verify(data)
    );
}

TEST_CASE("paserk_v2local", "[v2local]")
{
    std::string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
        key_paserk = key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_local.length(), paserk_local) == 0 );

    // Load a key from the paserk local key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *key == *key2 );
}

TEST_CASE("paserk_v2local_badkeys", "[v2local]")
{
    std::string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
        key_paserk = key->toPaserk();
    }

    // Load a key from the paserk local key-string
    // should fail if not v2_local
    {
        key2 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V2_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}

TEST_CASE("paserk_v2local_invalidkeylength", "[v2local]")
{
    std::string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
        key_paserk = key->toPaserk();
    }

    key2 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // test all substrings of a valid key
    for (size_t i=0; i<key_paserk.length(); i++)
    {
        std::string badkey = key_paserk.substr(0,i);
        REQUIRE_THROWS( key2->fromPaserk(badkey) );
    }

    // test with extra base-64 character (may be invalid base64 string)
    std::string bad_paserk_key = key_paserk;
    bad_paserk_key.append("a");
    REQUIRE_THROWS( key2->fromPaserk(bad_paserk_key) );    
}
