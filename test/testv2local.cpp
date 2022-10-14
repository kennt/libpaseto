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

string paserk_local = "k2.local.";
string paserk_lid = "k2.lid.";
string paserk_seal = "k2.seal.";
string paserk_wrap = "k2.local-wrap.pie.";
string paserk_pw = "k2.local-pw.";


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

    auto kid1 = key->toPaserkId();
    auto kid2 = key->toPaserkId();

    REQUIRE( kid1.compare(0, paserk_lid.length(), paserk_lid) == 0 );

    REQUIRE( kid1 == kid2 );
}


TEST_CASE("paserk_v2wrap_basic", "[paserk_v2local]")
{
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // basic usage test
    {
        auto encrypted_data = key->paserkWrap(wrapping_key.get());

        REQUIRE( encrypted_data.compare(0, paserk_wrap.length(), paserk_wrap) == 0 );

        auto restored_key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        restored_key->paserkUnwrap(encrypted_data, wrapping_key.get());


        REQUIRE( restored_key->is_loaded() );
        REQUIRE( restored_key->keyType() == paseto::KeyType::V2_LOCAL );
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

        auto restored_key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
        restored_key->paserkUnwrap(encrypted_key, wrapping_key.get());

        auto encrypted_data = key->encrypt(data);

        auto restored_data1 = key->decrypt(encrypted_data);
        auto restored_data2 = restored_key->decrypt(encrypted_data);

        REQUIRE( restored_data1.payload().toString() == data );
        REQUIRE( restored_data1.payload() == restored_data2.payload() );
    }
}


TEST_CASE("paserk_v2wrap_lucidity", "[paserk_v2local]")
{
    auto wrapping_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // same version, public/secret keys don't work
    REQUIRE_THROWS( key->paserkWrap(public_key.get()) );
    REQUIRE_THROWS( key->paserkWrap(secret_key.get()) );

    // check for other version, but local keys
    {
        auto key3 = paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto key4 = paseto::KeyGen::generate(paseto::KeyType::V4_LOCAL);

        REQUIRE( key3->is_loaded() );
        REQUIRE( key4->is_loaded() );

        REQUIRE_THROWS( key->paserkWrap(key3.get()) );
        REQUIRE_THROWS( key->paserkWrap(key4.get()) );
    }
}

// local-pw
TEST_CASE("paserk_v2pw_basic", "[paserk_v2local]")
{
    struct paseto::PasswordParams params;
    params.params.v2.time = 1024;
    params.params.v2.memory = 65536;
    params.params.v2.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // wrap the key with a password
    auto key_pw = key->paserkPasswordWrap("test-pass", &params);

    REQUIRE( key_pw.compare(0, paserk_pw.length(), paserk_pw) == 0 );

    // restore the key from the password-wrapped key
    auto restored_key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
    restored_key->paserkPasswordUnwrap(key_pw, "test-pass");

    REQUIRE( *key == *restored_key );
}


TEST_CASE("paserk_v2pw_noparams", "[paserk_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    // wrap the key with a password
    REQUIRE_THROWS( key->paserkPasswordWrap("test-pass", nullptr) );
}


TEST_CASE("paserk_v2pw_lucidity", "[paserk_v2local]")
{
    struct paseto::PasswordParams opts;
    opts.params.v2.time = 1024;
    opts.params.v2.memory = 65536;
    opts.params.v2.parallelism = 1;
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // wrap the key with a password
    auto key_pw = key->paserkPasswordWrap("test-pass", &opts);

    // same version, public keys don't work
    REQUIRE_THROWS( public_key->paserkPasswordWrap("test-pass", &opts) );

    // public/secret keys are not the recipients
    REQUIRE_THROWS( public_key->paserkPasswordUnwrap(key_pw, "test-pass") );
    REQUIRE_THROWS( secret_key->paserkPasswordUnwrap(key_pw, "test-pass") );

    // check for other version, but local keys
    {
        auto key3 = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        auto key4 = paseto::Keys::create(paseto::KeyType::V4_LOCAL);

        REQUIRE_THROWS( key3->paserkPasswordUnwrap(key_pw, "test-pass") );
        REQUIRE_THROWS( key4->paserkPasswordUnwrap(key_pw, "test-pass") );
    }
}

// seal
TEST_CASE("paserk_v2seal_basic", "[paserk_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);

    // seal the key with a public-key
    auto key_seal = key->paserkSeal(public_key.get());

    REQUIRE( key_seal.compare(0, paserk_seal.length(), paserk_seal) == 0 );

    // unseal the key with the secret-key
    auto restored_key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
    restored_key->paserkUnseal(key_seal, secret_key.get());

    REQUIRE( restored_key->is_loaded() );
    REQUIRE( *key == *restored_key );
}


TEST_CASE("paserk_v2seal_noparams", "[paserk_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    REQUIRE_THROWS( key->paserkSeal(nullptr) );
    REQUIRE_THROWS( key->paserkUnseal("dummy-data", nullptr) );
}


TEST_CASE("paserk_v2seal_lucidity", "[paserk_v2local]")
{
    auto key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

    auto local_key = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
    auto [ public_key, secret_key ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V2_PUBLIC);
    auto [ public_key3, secret_key3 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);
    auto [ public_key4, secret_key4 ] =
        paseto::KeyGen::generatePair(paseto::KeyType::V4_PUBLIC);

    // only public-keys are used to seal
    REQUIRE_THROWS( key->paserkSeal(secret_key.get()) );
    REQUIRE_THROWS( key->paserkSeal(local_key.get()) );

    REQUIRE_THROWS( key->paserkSeal(public_key3.get()) );
    REQUIRE_THROWS( key->paserkSeal(secret_key3.get()) );

    REQUIRE_THROWS( key->paserkSeal(public_key4.get()) );
    REQUIRE_THROWS( key->paserkSeal(secret_key4.get()) );

    // seal the key with a public-key
    auto key_seal = key->paserkSeal(public_key.get());


    // check that that only secret-keys are used to unseal
    auto restored_key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
    REQUIRE( !restored_key->is_loaded() );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, local_key.get()) );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key3.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, secret_key3.get()) );

    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, public_key4.get()) );
    REQUIRE_THROWS( restored_key->paserkUnseal(key_seal, secret_key4.get()) );

    REQUIRE( !restored_key->is_loaded() );
}
