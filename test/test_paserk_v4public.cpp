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
static string paserk_seal = "k4.seal.";


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

    // Load a key from the paserk public key-string
    // should fail if not v4_public
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

    auto kid1 = public_key->paserkId();
    auto kid2 = public_key->paserkId();

    REQUIRE( kid1.compare(0, paserk_pid.length(), paserk_pid) == 0 );

    REQUIRE( kid1 == kid2 );
}


// seal
TEST_CASE("paserk_v4seal_basic", "[paserk_v4public]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // seal the key with a public-key
    auto key_seal = public_key->seal(key.get());

    REQUIRE( key_seal.compare(0, paserk_seal.length(), paserk_seal) == 0 );

    // unseal the key with the secret-key
    auto restored_key = secret_key->unseal(key_seal);


    REQUIRE( restored_key->is_loaded() );
    REQUIRE( restored_key->keyType() == paseto::KeyType::V4_LOCAL );
    REQUIRE( *key == *restored_key );

    // Test that the keys function the same
    {
        string test_data {"my-test-data"};
        auto encrypted_data = key->encrypt(test_data);
        auto token = restored_key->decrypt(encrypted_data);
        REQUIRE(token.payload().toString() == test_data);
    }
}


TEST_CASE("paserk_v4seal_noparams", "[paserk_v4public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    REQUIRE_THROWS( public_key->seal(nullptr) );
    REQUIRE_THROWS( secret_key->unseal("") );
}


TEST_CASE("paserk_v4seal_lucidity", "[paserk_v4public]")
{

    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    auto local_key2 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto [ public_key2, secret_key2 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto local_key3 = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
    auto [ public_key3, secret_key3 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // only public-keys can be used to seal
    REQUIRE_THROWS( secret_key->seal(local_key.get()) );
    REQUIRE_THROWS( local_key->seal(local_key.get()) );

    REQUIRE_THROWS( public_key2->seal(local_key.get()) );
    REQUIRE_THROWS( secret_key2->seal(local_key.get()) );

    REQUIRE_THROWS( public_key3->seal(local_key.get()) );
    REQUIRE_THROWS( secret_key3->seal(local_key.get()) );

    // we can only seal local keys
    REQUIRE_THROWS( public_key->seal(public_key.get()) );
    REQUIRE_THROWS( public_key->seal(secret_key.get()) );

    // version checks
    REQUIRE_THROWS( public_key->seal(local_key2.get()) );
    REQUIRE_THROWS( public_key->seal(local_key3.get()) );


    // seal the key with a public-key
    auto key_seal = public_key->seal(local_key.get());


    // check that that only secret-keys are used to unseal
    REQUIRE_THROWS( public_key->unseal(key_seal) );
    REQUIRE_THROWS( local_key->unseal(key_seal) );

    REQUIRE_THROWS( public_key2->unseal(key_seal) );
    REQUIRE_THROWS( secret_key2->unseal(key_seal) );

    REQUIRE_THROWS( public_key3->unseal(key_seal) );
    REQUIRE_THROWS( secret_key3->unseal(key_seal) );
}
