
extern "C"
{
#include "paseto.h"
#include "helpers.h"
};
#include "paseto.hpp"

#include <string>
using std::string;

#include <catch2/catch_test_macros.hpp>

TEST_CASE("paseto_v2_basic", "[paserk_v2]")
{
    auto key = paseto::Keys::create(paseto::KeyType::V2_LOCAL);
    string data {"test data"};

    // Test that create() returns an empty key that can't be used
    {
        REQUIRE( !key->is_loaded() );
        REQUIRE_THROWS( key->encrypt(data) );
    }

    // generate() should create different keys
    {
        auto key1 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);
        auto key2 = paseto::KeyGen::generate(paseto::KeyType::V2_LOCAL);

        REQUIRE( *key1 != *key2 );
    }
}


// basic v2_local
// basic v2_public
// basic v3_local
// basic v3_public
// basic v4_local
// basic v4_public
