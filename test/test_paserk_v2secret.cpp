extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_secret = "k2.secret.";
static string paserk_sid = "k2.sid.";
static string paserk_pw = "k2.secret-pw.";
static string paserk_wrap = "k2.secret-wrap.pie.";


TEST_CASE("paserk_v2secret_basic", "[paserk_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.public string
    {
        key_paserk = secret_key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_secret.length(), paserk_secret) == 0 );

    // Load a key from the paserk public key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_SECRET);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *secret_key == *key2 );
}


TEST_CASE("paserk_v2secret_lucidity", "[paserk_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    std::unique_ptr<paseto::Key> key2;
    string key_paserk;

    // Generate the k2.public string
    {
        key_paserk = secret_key->toPaserk();
    }

    // Load a key from the paserk local key-string
    // should fail if not v2_local
    {
        key2 = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V2_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v2secret_invalidkeylength", "[paserk_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k2.public string
    {
        key_paserk = secret_key->toPaserk();
    }

    key2 = paseto::Keys::create(paseto::KeyType::V2_SECRET);

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


TEST_CASE("paserk_v2sid_basic", "[paserk_v2secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    auto kid1 = secret_key->toPaserkId();
    auto kid2 = secret_key->toPaserkId();

    REQUIRE( kid1.compare(0, paserk_sid.length(), paserk_sid) == 0 );

    REQUIRE( kid1 == kid2 );
}


TEST_CASE("paserk_v2secretwrap_basic", "[paserk_v2local]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // basic usage test
    {
        auto encrypted_data = secret_key->paserkWrap(wrapping_key.get());

        REQUIRE( encrypted_data.compare(0, paserk_wrap.length(), paserk_wrap) == 0 );

        auto restored_key = paseto::Keys::create(paseto::KeyType::V2_SECRET);
        restored_key->paserkUnwrap(encrypted_data, wrapping_key.get());

        REQUIRE( restored_key->is_loaded() );
        REQUIRE( restored_key->keyType() == paseto::KeyType::V2_SECRET );
        REQUIRE( *secret_key == *restored_key );
    }

    // test that the wrapped keys are different (due to random nonce)
    {
        auto encrypted_key1 = secret_key->paserkWrap(wrapping_key.get());
        auto encrypted_key2 = secret_key->paserkWrap(wrapping_key.get());

        REQUIRE( encrypted_key1 != encrypted_key2 );
    }

    // test that sign/verify works
    {
        auto encrypted_key = secret_key->paserkWrap(wrapping_key.get());
        string data {"test data foo"};

        auto restored_key = paseto::Keys::create(paseto::KeyType::V2_SECRET);
        restored_key->paserkUnwrap(encrypted_key, wrapping_key.get());

        auto signed_data = restored_key->sign(data);

        auto verified_data1 = public_key->verify(signed_data);
        REQUIRE( verified_data1.payload().toString() == data );
    }
}


TEST_CASE("paserk_v2secretwrap_lucidity", "[paserk_v2local]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // same version, public/secret keys don't work
    REQUIRE_THROWS( secret_key->paserkWrap(public_key.get()) );
    REQUIRE_THROWS( secret_key->paserkWrap(secret_key.get()) );

    // check for other version, but local keys
    {
        auto key3 = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto key4 = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

        REQUIRE( key3->is_loaded() );
        REQUIRE( key4->is_loaded() );

        REQUIRE_THROWS( secret_key->paserkWrap(key3.get()) );
        REQUIRE_THROWS( secret_key->paserkWrap(key4.get()) );
    }
}


// local-pw
TEST_CASE("paserk_v2secretpw_basic", "[paserk_v2local]")
{
    struct paseto::PasswordParams params;
    params.params.v2.time = 1024;
    params.params.v2.memory = 65536;
    params.params.v2.parallelism = 1;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // wrap the key with a password
    auto key_pw = secret_key->paserkPasswordWrap("test-pass", &params);

    REQUIRE( key_pw.compare(0, paserk_pw.length(), paserk_pw) == 0 );

    // restore the key from the password-wrapped key
    auto restored_key = paseto::Keys::create(paseto::KeyType::V2_SECRET);
    restored_key->paserkPasswordUnwrap(key_pw, "test-pass");

    REQUIRE( *secret_key == *restored_key );
}


TEST_CASE("paserk_v2secretpw_noparams", "[paserk_v2local]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // wrap the key with a password
    REQUIRE_THROWS( secret_key->paserkPasswordWrap("test-pass", nullptr) );
}


TEST_CASE("paserk_v2secretpw_lucidity", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // wrap the key with a password
    auto key_pw = secret_key->paserkPasswordWrap("test-pass", &opts);

    // same version, public keys can't use password wrapping
    REQUIRE_THROWS( public_key->paserkPasswordWrap("test-pass", &opts) );

    // local/public keys cannot be recipients
    REQUIRE_THROWS( local_key->paserkPasswordUnwrap(key_pw, "test-pass") );
    REQUIRE_THROWS( public_key->paserkPasswordUnwrap(key_pw, "test-pass") );

    // check for other version, but secret keys
    {
        auto [ public_key3, secret_key3 ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);
        auto [ public_key4, secret_key4 ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

        REQUIRE_THROWS( secret_key3->paserkPasswordUnwrap(key_pw, "test-pass") );
        REQUIRE_THROWS( secret_key4->paserkPasswordUnwrap(key_pw, "test-pass") );
    }
}
