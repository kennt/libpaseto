extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_local = "k4.local.";
static string paserk_lid = "k4.lid.";
static string paserk_seal = "k4.seal.";
static string paserk_wrap = "k4.local-wrap.pie.";
static string paserk_pw = "k4.local-pw.";


TEST_CASE("paserk_v4local_basic", "[paserk_v4local]")
{
    string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k4.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
        key_paserk = key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_local.length(), paserk_local) == 0 );

    // Load a key from the paserk local key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *key == *key2 );
}


TEST_CASE("paserk_v4local_lucidity", "[paserk_v4local]")
{
    string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k4.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
        key_paserk = key->toPaserk();
    }

    // Load a key from the paserk local key-string
    // should fail if not v4_local
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v4local_invalidkeylength", "[paserk_v4local]")
{
    string key_paserk;
    std::unique_ptr<paseto::Key> key;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.local string
    {
        key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
        key_paserk = key->toPaserk();
    }

    key2 = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

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


TEST_CASE("paserk_v4lid_basic", "[paserk_v4local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    auto kid1 = key->paserkId();
    auto kid2 = key->paserkId();

    REQUIRE( kid1.compare(0, paserk_lid.length(), paserk_lid) == 0 );

    REQUIRE( kid1 == kid2 );
}


TEST_CASE("paserk_v4localwrap_basic", "[paserk_v4local]")
{
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    // basic usage test
    {
        auto encrypted_data = key->paserkWrap(wrapping_key.get());

        REQUIRE( encrypted_data.compare(0, paserk_wrap.length(), paserk_wrap) == 0 );

        auto restored_key = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
        restored_key->paserkUnwrap(encrypted_data, wrapping_key.get());


        REQUIRE( restored_key->is_loaded() );
        REQUIRE( restored_key->keyType() == paseto::KeyType::V4_LOCAL );
        REQUIRE( *key == *restored_key );
    }

    // test that the wrapped keys are different (due to random nonce)
    {
        auto encrypted_key1 = key->paserkWrap(wrapping_key.get());
        auto encrypted_key2 = key->paserkWrap(wrapping_key.get());

        REQUIRE( encrypted_key1 != encrypted_key2 );
    }

    // test that encrypt/decrypt works
    {
        auto encrypted_key = key->paserkWrap(wrapping_key.get());
        string data {"test data foo"};

        auto restored_key = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
        restored_key->paserkUnwrap(encrypted_key, wrapping_key.get());

        auto encrypted_data = key->encrypt(data);

        auto restored_data1 = key->decrypt(encrypted_data);
        auto restored_data2 = restored_key->decrypt(encrypted_data);

        REQUIRE( restored_data1.payload().toString() == data );
        REQUIRE( restored_data1.payload() == restored_data2.payload() );
    }
}


TEST_CASE("paserk_v4localwrap_lucidity", "[paserk_v4local]")
{
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // same version, public/secret keys don't work
    REQUIRE_THROWS( key->paserkWrap(public_key.get()) );
    REQUIRE_THROWS( key->paserkWrap(secret_key.get()) );

    // check for other version, but local keys
    {
        auto key2 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
        auto key3 = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);

        REQUIRE( key2->is_loaded() );
        REQUIRE( key3->is_loaded() );

        REQUIRE_THROWS( key->paserkWrap(key2.get()) );
        REQUIRE_THROWS( key->paserkWrap(key3.get()) );
    }
}

// local-pw
TEST_CASE("paserk_v4localpw_basic", "[paserk_v4local]")
{
    struct paseto::PasswordParams params;
    params.params.v4.time = 1024;
    params.params.v4.memory = 65536;
    params.params.v4.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    // wrap the key with a password
    auto key_pw = key->paserkPasswordWrap("test-pass", &params);

    REQUIRE( key_pw.compare(0, paserk_pw.length(), paserk_pw) == 0 );

    // restore the key from the password-wrapped key
    auto restored_key = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
    restored_key->paserkPasswordUnwrap(key_pw, "test-pass");

    REQUIRE( *key == *restored_key );
}


TEST_CASE("paserk_v4localpw_noparams", "[paserk_v4local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    // wrap the key with a password
    REQUIRE_THROWS( key->paserkPasswordWrap("test-pass", nullptr) );
}


TEST_CASE("paserk_v4localpw_lucidity", "[paserk_v4local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v4.time = 1024;
    opts.params.v4.memory = 65536;
    opts.params.v4.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // wrap the key with a password
    auto key_pw = key->paserkPasswordWrap("test-pass", &opts);

    // same version, public keys don't work
    REQUIRE_THROWS( public_key->paserkPasswordWrap("test-pass", &opts) );

    // public/secret keys are not the recipients
    REQUIRE_THROWS( public_key->paserkPasswordUnwrap(key_pw, "test-pass") );
    REQUIRE_THROWS( secret_key->paserkPasswordUnwrap(key_pw, "test-pass") );

    // check for other version, but local keys
    {
        auto key2 = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        auto key3 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);

        REQUIRE_THROWS( key2->paserkPasswordUnwrap(key_pw, "test-pass") );
        REQUIRE_THROWS( key3->paserkPasswordUnwrap(key_pw, "test-pass") );
    }
}

// seal
TEST_CASE("paserk_v4seal_basic", "[paserk_v4local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // seal the key with a public-key
    auto key_seal = key->paserkSeal(public_key.get());

    REQUIRE( key_seal.compare(0, paserk_seal.length(), paserk_seal) == 0 );

    // unseal the key with the secret-key
    auto restored_key = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
    restored_key->paserkUnseal(key_seal, secret_key.get());

    REQUIRE( restored_key->is_loaded() );
    REQUIRE( *key == *restored_key );

    // Test that the keys function the same
    {
        string test_data {"my-test-data"};
        auto encrypted_data = key->encrypt(test_data);
        auto token = restored_key->decrypt(encrypted_data);
        REQUIRE(token.payload().toString() == test_data);
    }
}


TEST_CASE("paserk_v4seal_noparams", "[paserk_v4local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    REQUIRE_THROWS( key->paserkSeal(nullptr) );
    REQUIRE_THROWS( key->paserkUnseal("dummy-data", nullptr) );
}


TEST_CASE("paserk_v4seal_lucidity", "[paserk_v4local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);
    auto [ public_key2, secret_key2 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto [ public_key3, secret_key3 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // only public-keys are used to seal
    REQUIRE_THROWS( key->paserkSeal(secret_key.get()) );
    REQUIRE_THROWS( key->paserkSeal(local_key.get()) );

    REQUIRE_THROWS( key->paserkSeal(public_key2.get()) );
    REQUIRE_THROWS( key->paserkSeal(secret_key2.get()) );

    REQUIRE_THROWS( key->paserkSeal(public_key3.get()) );
    REQUIRE_THROWS( key->paserkSeal(secret_key3.get()) );

    // seal the key with a public-key
    auto key_seal = key->paserkSeal(public_key.get());


    // check that that only secret-keys are used to unseal
    auto restored_key = paseto::Keys::create(paseto::KeyType::V4_LOCAL);
    REQUIRE( !restored_key->is_loaded() );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, local_key.get()) );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key2.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, secret_key2.get()) );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key3.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, secret_key3.get()) );

    REQUIRE( !restored_key->is_loaded() );
}
