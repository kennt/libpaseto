extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_local = "k2.local.";
static string paserk_lid = "k2.lid.";
static string paserk_local_wrap = "k2.local-wrap.pie.";
static string paserk_secret_wrap = "k2.secret-wrap.pie.";
static string paserk_pw = "k2.local-pw.";


TEST_CASE("paserk_v2local_basic", "[paserk_v2local]")
{
    string key_paserk;
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


TEST_CASE("paserk_v2local_lucidity", "[paserk_v2local]")
{
    string key_paserk;
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

        key2 = paseto::Keys::create(paseto::KeyType::V2_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v2local_invalidkeylength", "[paserk_v2local]")
{
    string key_paserk;
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
        string badkey = key_paserk.substr(0,i);
        REQUIRE_THROWS( key2->fromPaserk(badkey) );
    }

    // test with extra base-64 character (may be invalid base64 string)
    string bad_paserk_key = key_paserk;
    bad_paserk_key.append("a");
    REQUIRE_THROWS( key2->fromPaserk(bad_paserk_key) );
}


TEST_CASE("paserk_v2lid_basic", "[paserk_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto kid1 = key->paserkId();
    auto kid2 = key->paserkId();

    REQUIRE( kid1.compare(0, paserk_lid.length(), paserk_lid) == 0 );

    REQUIRE( kid1 == kid2 );
}


TEST_CASE("paserk_v2localwrap_basic", "[paserk_v2local]")
{
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // basic usage test
    {
        auto encrypted_data = wrapping_key->wrap(key.get());

        REQUIRE( encrypted_data.compare(0, paserk_local_wrap.length(), paserk_local_wrap) == 0 );

        auto restored_key = wrapping_key->unwrap(encrypted_data);

        REQUIRE( restored_key->is_loaded() );
        REQUIRE( restored_key->keyType() == paseto::KeyType::V2_LOCAL );
        REQUIRE( *key == *restored_key );
    }

    // test that the wrapped keys are different (due to random nonce)
    {
        auto encrypted_key1 = wrapping_key->wrap(key.get());
        auto encrypted_key2 = wrapping_key->wrap(key.get());

        REQUIRE( encrypted_key1 != encrypted_key2 );
    }

    // test that encrypt/decrypt works
    {
        auto encrypted_key = wrapping_key->wrap(key.get());
        auto restored_key = wrapping_key->unwrap(encrypted_key);

        string data {"test-data"};
        auto encrypted_data = key->encrypt(data);

        auto restored_data1 = key->decrypt(encrypted_data);
        auto restored_data2 = restored_key->decrypt(encrypted_data);

        REQUIRE( restored_data1.payload().toString() == data );
        REQUIRE( restored_data1.payload() == restored_data2.payload() );
    }
}

TEST_CASE("paserk_v2secretwrap_basic", "[paserk_v2local]")
{
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // basic usage test
    {
        auto encrypted_data = local_key->wrap(secret_key.get());

        REQUIRE( encrypted_data.compare(0, paserk_secret_wrap.length(), paserk_secret_wrap) == 0 );

        auto restored_key = local_key->unwrap(encrypted_data);

        REQUIRE( restored_key->is_loaded() );
        REQUIRE( restored_key->keyType() == paseto::KeyType::V2_SECRET );
        REQUIRE( *secret_key == *restored_key );
    }

    // test that the wrapped keys are different (due to random nonce)
    {
        auto encrypted_key1 = local_key->wrap(secret_key.get());
        auto encrypted_key2 = local_key->wrap(secret_key.get());

        REQUIRE( encrypted_key1 != encrypted_key2 );
    }

    // test that sign/verify works
    {
        auto encrypted_key = local_key->wrap(secret_key.get());
        string data {"test data foo"};

        auto restored_key = local_key->unwrap(encrypted_key);

        auto signed_data = restored_key->sign(data);
        auto restored_data = public_key->verify(signed_data);

        REQUIRE( restored_data.payload().toString() == data );
    }
}


TEST_CASE("paserk_v2wrap_lucidity", "[paserk_v2local]")
{
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // we don't wrap public keys
    REQUIRE_THROWS( local_key->wrap(public_key.get()) );

    // same version, public/secret keys don't work
    REQUIRE_THROWS( public_key->wrap(local_key.get()) );
    REQUIRE_THROWS( secret_key->wrap(local_key.get()) );

    // check for other version, but local keys
    {
        auto key3 = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto key4 = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

        REQUIRE( key3->is_loaded() );
        REQUIRE( key4->is_loaded() );

        REQUIRE_THROWS( key3->wrap(local_key.get()) );
        REQUIRE_THROWS( key4->wrap(local_key.get()) );
    }
}

// local-pw
TEST_CASE("paserk_v2localpw_basic", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // wrap the key with a password
    auto key_pw = paserk::passwordWrap(key.get(), "test-pass", &opts);

    REQUIRE( key_pw.compare(0, paserk_pw.length(), paserk_pw) == 0 );

    // restore the key from the password-wrapped key
    auto restored_key = paserk::passwordUnwrap(key_pw, "test-pass");

    REQUIRE( restored_key->is_loaded() );
    REQUIRE( restored_key->keyType() == paseto::KeyType::V2_LOCAL );
    REQUIRE( *key == *restored_key );
}


TEST_CASE("paserk_v2localpw_noparams", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // wrap the key with a password
    REQUIRE_THROWS( paserk::passwordWrap(nullptr, "test-pass", &opts) );
    REQUIRE_THROWS( paserk::passwordWrap(key.get(), "test-pass", nullptr) );
}


TEST_CASE("paserk_v2localpw_badpassword", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // wrap the key with a password
    auto paserk_pw = paserk::passwordWrap(key.get(), "test-pass", &opts);

    REQUIRE_THROWS( paserk::passwordUnwrap(paserk_pw, "bad-password!") );
}


TEST_CASE("paserk_v2localpw_lucidity", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // same version, can't wrap public keys
    REQUIRE_THROWS( paserk::passwordWrap(public_key.get(), "test-pass", &opts) );
}
