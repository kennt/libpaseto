extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_public = "k4.public.";
static string paserk_pid = "k4.pid.";


TEST_CASE("paserk_v4public_basic", "[paserk_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k4.public string
    {
        key_paserk = public_key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_public.length(), paserk_public) == 0 );

    // Load a key from the paserk public key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V4_PUBLIC);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *public_key == *key2 );
}


TEST_CASE("paserk_v4public_lucidity", "[paserk_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    std::unique_ptr<paseto::Key> key2;
    string key_paserk;

    // Generate the k4.public string
    {
        key_paserk = public_key->toPaserk();
    }

    // Load a key from the paserk local key-string
    // should fail if not v4_local
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v4public_invalidkeylength", "[paserk_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k4.public string
    {
        key_paserk = public_key->toPaserk();
    }

    key2 = paseto::Keys::create(paseto::KeyType::V4_PUBLIC);

    // test all substrings of a valid key
    for (size_t i=0; i<key_paserk.length(); i++)
    {
        string badkey = key_paserk.substr(0,i);
        REQUIRE_THROWS( key2->fromPaserk(badkey) );
    }

    // test with extra base-64 character (may be invalid base64 string)
    string bad_paserk_key = key_paserk;
    bad_paserk_key.append("a");
    REQUIRE_THROWS( key2->fromPaserk(bad_paserk_key) );
}


TEST_CASE("paserk_v4pid_basic", "[paserk_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    auto kid1 = public_key->toPaserkId();
    auto kid2 = public_key->toPaserkId();

    REQUIRE( kid1.compare(0, paserk_pid.length(), paserk_pid) == 0 );

    REQUIRE( kid1 == kid2 );
}
