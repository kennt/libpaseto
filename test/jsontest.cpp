
extern "C"
{
#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
};


#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <cstdio>

#define DEBUG
#include "paseto.hpp"

using json = nlohmann::json;
using namespace std;

size_t getNonceLength(paseto::KeyType k)
{
    switch (paseto::KeyTypeVersion(k))
    {
        case 2: return paseto_v2_LOCAL_NONCEBYTES;
        case 3: return paseto_v3_LOCAL_NONCEBYTES;
        case 4: return paseto_v4_LOCAL_NONCEBYTES;
        default: return 0;
    }
}

void run_test_vector(const string path,
                     paseto::KeyType local_encode_keytype,
                     paseto::KeyType local_dedode_keytype,
                     paseto::KeyType public_encode_keytype,
                     paseto::KeyType public_decode_keytype);


int main(int argc, char **argv)
{
    run_test_vector("test/v2.json",
                    paseto::KeyType::V2_LOCAL,
                    paseto::KeyType::V2_LOCAL,
                    paseto::KeyType::V2_SECRET,
                    paseto::KeyType::V2_PUBLIC
                    );
    run_test_vector("test/v3.json",
                    paseto::KeyType::V3_LOCAL,
                    paseto::KeyType::V3_LOCAL,
                    paseto::KeyType::V3_SECRET,
                    paseto::KeyType::V3_PUBLIC
                    );
    run_test_vector("test/v4.json",
                    paseto::KeyType::V4_LOCAL,
                    paseto::KeyType::V4_LOCAL,
                    paseto::KeyType::V4_SECRET,
                    paseto::KeyType::V4_PUBLIC
                    );
}


void run_test_vector(const string pathToFile,
                     paseto::KeyType local_encode_keytype,
                     paseto::KeyType local_decode_keytype,
                     paseto::KeyType public_encode_keytype,
                     paseto::KeyType public_decode_keytype)
{
    try
    {
        json j;

        // v2
        assert(filesystem::exists(pathToFile));
        ifstream fstream(pathToFile);
        j = json::parse(fstream);
        cout << "----------------------------------------" << endl;
        cout << "File: " << pathToFile
                  << "  Name: " << j["name"] << endl;

        for (const auto& element : j["tests"])
        {
            string name = element["name"].get<string>();
            bool expect_fail = element["expect-fail"].get<bool>();
            string result;
            string stoken = element["token"].get<string>();
            string footer = element["footer"].get<string>();
            string implicit_assertion = element["implicit-assertion"].get<string>();
            string payload;

            cout << "Test: " <<  name;
            cout << "  expect-fail:" << expect_fail;

            if (element.contains("public-key"))
            {
                string spublic_key = element["public-key"].get<string>();
                string ssecret_key = element["secret-key"].get<string>();
                string seed;
                if (element.contains("secret-key-seed"))
                {
                    seed = element["secret-key-seed"].get<string>();
                    auto seed_bytes = paseto::Binary::fromHex(seed);
                    auto key_pair = paseto::KeyGen::generatePair(
                                        public_decode_keytype, seed_bytes);
                    if (key_pair.first->toHex() != spublic_key)
                        cerr << "Seed-generated public key doesn't match up" << endl;
                    if (key_pair.second->toHex() != ssecret_key)
                        cerr << "Seed-generated secret key doesn't match up" << endl;
                }
                paseto::BinaryVector payload_bytes;
                if (!element["payload"].is_null())
                {
                    payload = element["payload"].get<string>();
                    payload_bytes = paseto::Binary::fromString(payload);
                }
                paseto::BinaryVector footer_bytes = 
                            paseto::Binary::fromString(footer);
                paseto::BinaryVector ia_bytes;
                if (KeyTypeVersion(local_encode_keytype) > 2)
                    ia_bytes = paseto::Binary::fromString(implicit_assertion);
                bool test_ok = true;

                auto seckey = paseto::Keys::loadFromHex(
                        public_encode_keytype, ssecret_key);

                auto pubkey = paseto::Keys::loadFromHex(
                        public_decode_keytype, spublic_key);

                try
                {
                    result = seckey->sign(payload_bytes, footer_bytes, ia_bytes);
                }
                catch (exception &ex)
                {
                    test_ok = false;
                }
                if (test_ok)
                    test_ok = (!result.empty() && (stoken == result));
                if (!result.empty())
                    cout << "  result:" << test_ok;
                else
                    cout << "  result:" << "null";
                if (test_ok != expect_fail)
                    cout << " signing:pass";
                else
                    cout << " signing:FAILED";

                paseto::Token token;
                test_ok = true;
                try
                {
                    token = pubkey->verify(stoken, ia_bytes);
                }
                catch (exception)
                {
                    test_ok = false;
                }

                if (test_ok)
                    test_ok = (!token.payload().empty() && (payload_bytes == token.payload()));
                if (!token.payload().empty())
                    cout << "  result:" << (token.payload() == payload_bytes);
                else
                    cout << "  result:" << "null";

                if (test_ok != expect_fail)
                    cout << " verify:pass";
                else
                    cout << " verify:FAILED";

                //cout << " result:" << (token.payload() == payload_bytes);
                cout << endl;
                //cout << "stoken:" << stoken << std::endl;
                //cout << "result:" << result << std::endl;
            }
            else
            {
                string skey = element["key"].get<string>();
                string nonce = element["nonce"].get<string>();

                // encryption test
                {
                    paseto::BinaryVector payload_bytes;
                    paseto::BinaryVector footer_bytes = 
                            paseto::Binary::fromString(footer);
                    paseto::BinaryVector ia_bytes;
                    if (KeyTypeVersion(local_encode_keytype) > 2)
                        ia_bytes = paseto::Binary::fromString(implicit_assertion);
                    bool test_ok = true;

                    if (!element["payload"].is_null())
                    {
                        payload = element["payload"].get<string>();
                        payload_bytes = paseto::Binary::fromString(payload);
                    }

                    unique_ptr<paseto::Key> key =
                            paseto::Keys::loadFromHex(local_encode_keytype, skey);

                    if (nonce.length() == 2 * getNonceLength(local_encode_keytype))
                    {
                        key->setNonce(nonce, payload_bytes);
                        test_ok = true;

                        try
                        {
                            result = key->encrypt(payload_bytes, footer_bytes, ia_bytes);
                        }
                        catch (exception ex)
                        {
                            test_ok = false;
                        }

                        key->clearNonce();
                    }
                    if (test_ok)
                        test_ok = (!result.empty() && (stoken == result));
                    if (!result.empty())
                        cout << "  result:" << test_ok;
                    else
                        cout << "  result:" << "null";

                    if (test_ok != expect_fail)
                        cout << " encrypt:pass ";
                    else
                        cout << " encrypt:FAILED ";
                    result.clear();
                }

                // decryption test
                {
                    paseto::BinaryVector payload_bytes;
                    paseto::BinaryVector footer_bytes = paseto::Binary::fromString(footer);
                    paseto::BinaryVector ia_bytes;
                    if (KeyTypeVersion(local_encode_keytype) > 2)
                        ia_bytes = paseto::Binary::fromString(implicit_assertion);
                    bool test_ok = true;

                    if (!element["payload"].is_null())
                    {
                        payload = element["payload"].get<string>();
                        payload_bytes = paseto::Binary::fromString(payload);
                    }

                    auto key = paseto::Keys::loadFromHex(
                         local_decode_keytype, skey);

                    paseto::Token token;

                    if (nonce.length() == 2 * getNonceLength(local_encode_keytype))
                    {
                        try
                        {
                            token = key->decrypt(stoken, ia_bytes);
                        }
                        catch (exception ex)
                        {
                            test_ok = false;
                        }
                    }
                
                    if (test_ok)
                    {
                        test_ok = (token.payload() == payload_bytes);
                        test_ok = test_ok && (token.footer() == footer_bytes);
                    }
                    if (!token.payload().empty())
                        cout << " result:" << test_ok;
                    else
                        cout << " result:" << "null";

                    if (test_ok != expect_fail)
                        cout << " decrypt:pass";
                    else
                        cout << " decrypt:FAILED";
                }

                cout << endl;
            }
        }
    }
    catch (exception &ex)
    {
        cout << endl << ex.what() << endl;
        cout << "caught an exception, continuing..." << endl;
    }
    return;
}
