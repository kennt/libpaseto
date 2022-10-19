extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_public = "k3.public.";
static string paserk_pid = "k3.pid.";
static string paserk_seal = "k3.seal.";


TEST_CASE("paserk_v3public_basic", "[paserk_v3public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k3.public string
    {
        key_paserk = public_key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_public.length(), paserk_public) == 0 );

    // Load a key from the paserk public key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V3_PUBLIC);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *public_key == *key2 );
}


TEST_CASE("paserk_v3public_lucidity", "[paserk_v3public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    std::unique_ptr<paseto::Key> key2;
    string key_paserk;

    // Generate the k3.public string
    {
        key_paserk = public_key->toPaserk();
    }

    // Load a key from the paserk local key-string
    // should fail if not v3_local
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v3public_invalidkeylength", "[paserk_v3public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k3.public string
    {
        key_paserk = public_key->toPaserk();
    }

    key2 = paseto::Keys::create(paseto::KeyType::V3_PUBLIC);

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


TEST_CASE("paserk_v3pid_basic", "[paserk_v3public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    auto kid1 = public_key->paserkId();
    auto kid2 = public_key->paserkId();

    REQUIRE( kid1.compare(0, paserk_pid.length(), paserk_pid) == 0 );

    REQUIRE( kid1 == kid2 );
}


// seal
TEST_CASE("paserk_v3seal_basic", "[paserk_v3public]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // seal the key with a public-key
    auto key_seal = public_key->seal(key.get());

    REQUIRE( key_seal.compare(0, paserk_seal.length(), paserk_seal) == 0 );

    // unseal the key with the secret-key
    auto restored_key = secret_key->unseal(key_seal);


    REQUIRE( restored_key->is_loaded() );
    REQUIRE( restored_key->keyType() == paseto::KeyType::V3_LOCAL );
    REQUIRE( *key == *restored_key );

    // Test that the keys function the same
    {
        string test_data {"my-test-data"};
        auto encrypted_data = key->encrypt(test_data);
        auto token = restored_key->decrypt(encrypted_data);
        REQUIRE(token.payload().toString() == test_data);
    }
}


TEST_CASE("paserk_v3seal_noparams", "[paserk_v3public]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    REQUIRE_THROWS( public_key->seal(nullptr) );
    REQUIRE_THROWS( secret_key->unseal("") );
}


TEST_CASE("paserk_v3seal_lucidity", "[paserk_v3public]")
{

    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    auto local_key2 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto [ public_key2, secret_key2 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto local_key4 = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto [ public_key4, secret_key4 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // only public-keys can be used to seal
    REQUIRE_THROWS( secret_key->seal(local_key.get()) );
    REQUIRE_THROWS( local_key->seal(local_key.get()) );

    REQUIRE_THROWS( public_key2->seal(local_key.get()) );
    REQUIRE_THROWS( secret_key2->seal(local_key.get()) );

    REQUIRE_THROWS( public_key4->seal(local_key.get()) );
    REQUIRE_THROWS( secret_key4->seal(local_key.get()) );

    // we can only seal local keys
    REQUIRE_THROWS( public_key->seal(public_key.get()) );
    REQUIRE_THROWS( public_key->seal(secret_key.get()) );

    // version checks
    REQUIRE_THROWS( public_key->seal(local_key2.get()) );
    REQUIRE_THROWS( public_key->seal(local_key4.get()) );


    // seal the key with a public-key
    auto key_seal = public_key->seal(local_key.get());


    // check that that only secret-keys are used to unseal
    REQUIRE_THROWS( public_key->unseal(key_seal) );
    REQUIRE_THROWS( local_key->unseal(key_seal) );

    REQUIRE_THROWS( public_key2->unseal(key_seal) );
    REQUIRE_THROWS( secret_key2->unseal(key_seal) );

    REQUIRE_THROWS( public_key4->unseal(key_seal) );
    REQUIRE_THROWS( secret_key4->unseal(key_seal) );
}
