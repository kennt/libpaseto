extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

static string paserk_secret = "k3.secret.";
static string paserk_sid = "k3.sid.";
static string paserk_pw = "k3.secret-pw.";
static string paserk_wrap = "k3.secret-wrap.pie.";


TEST_CASE("paserk_v3secret_basic", "[paserk_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k3.secret string
    {
        key_paserk = secret_key->toPaserk();
    }

    REQUIRE( key_paserk.compare(0, paserk_secret.length(), paserk_secret) == 0 );

    // Load a key from the paserk public key-string
    {
        key2 = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        REQUIRE( !key2->is_loaded() );

        key2->fromPaserk(key_paserk);
        REQUIRE( key2->is_loaded() );
    }

    REQUIRE( *secret_key == *key2 );
}


TEST_CASE("paserk_v3secret_lucidity", "[paserk_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    std::unique_ptr<paseto::Key> key2;
    string key_paserk;

    // Generate the k3.secret string
    {
        key_paserk = secret_key->toPaserk();
    }

    // Load a key from the paserk secret key-string
    // should fail if not v3_secret
    {
        key2 = paseto::Keys::create(paseto::KeyType::V2_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V4_SECRET);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );

        key2 = paseto::Keys::create(paseto::KeyType::V3_PUBLIC);
        REQUIRE_THROWS( key2->fromPaserk(key_paserk) );
    }
}


TEST_CASE("paserk_v3secret_invalidkeylength", "[paserk_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    string key_paserk;
    std::unique_ptr<paseto::Key> key2;

    // Generate the k3.secret string
    {
        key_paserk = secret_key->toPaserk();
    }

    key2 = paseto::Keys::create(paseto::KeyType::V3_SECRET);

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


TEST_CASE("paserk_v3sid_basic", "[paserk_v3secret]")
{
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    auto kid1 = secret_key->paserkId();
    auto kid2 = secret_key->paserkId();

    REQUIRE( kid1.compare(0, paserk_sid.length(), paserk_sid) == 0 );

    REQUIRE( kid1 == kid2 );
}


// secret-pw
TEST_CASE("paserk_v3secretpw_basic", "[paserk_v3secret]")
{
    struct paseto::PasswordParams opts;
    opts.params.v3.iterations = 1024;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // wrap the key with a password
    auto key_pw = paserk::passwordWrap(secret_key.get(), "test-pass", &opts);

    REQUIRE( key_pw.compare(0, paserk_pw.length(), paserk_pw) == 0 );

    // restore the key from the password-wrapped key
    auto restored_key = paserk::passwordUnwrap(key_pw, "test-pass");

    REQUIRE( restored_key->is_loaded() );
    REQUIRE( restored_key->keyType() == paseto::KeyType::V3_SECRET );
    REQUIRE( *secret_key == *restored_key );
}


TEST_CASE("paserk_v3secretpw_noparams", "[paserk_v3secret]")
{
    struct paseto::PasswordParams opts;
    opts.params.v3.iterations = 1024;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // wrap the key with a password
    REQUIRE_THROWS( paserk::passwordWrap(nullptr, "test-pass", &opts) );
    REQUIRE_THROWS( paserk::passwordWrap(secret_key.get(), "test-pass", nullptr) );
}


TEST_CASE("paserk_v3secretpw_badpassword", "[paserk_v3secret]")
{
    struct paseto::PasswordParams opts;
    opts.params.v3.iterations = 1024;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // wrap the key with a password
    auto paserk_pw = paserk::passwordWrap(secret_key.get(), "test-pass", &opts);

    REQUIRE_THROWS( paserk::passwordUnwrap(paserk_pw, "bad-password!") );
}


TEST_CASE("paserk_v3secretpw_lucidity", "[paserk_v3secret]")
{
    struct paseto::PasswordParams opts;
    opts.params.v3.iterations = 1024;
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

    // same version, can't wrap public keys
    REQUIRE_THROWS( paserk::passwordWrap(public_key.get(), "test-pass", &opts) );
}
