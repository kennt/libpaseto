
#include "paseto.h"
#include "helpers.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#define DEBUG
#include "paseto.hpp"

using json = nlohmann::json;

void run_test_vector(const std::string path,
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


void run_test_vector(const std::string pathToFile,
                     paseto::KeyType local_encode_keytype,
                     paseto::KeyType local_decode_keytype,
                     paseto::KeyType public_encode_keytype,
                     paseto::KeyType public_decode_keytype)
{
    try
    {
        json j;

        // v2
        assert(std::filesystem::exists(pathToFile));
        std::ifstream fstream(pathToFile);
        j = json::parse(fstream);
        std::cout << "----------------------------------------" << std::endl;
        std::cout << "File: " << pathToFile
                  << "  Name: " << j["name"] << std::endl;

        for (const auto& element : j["tests"])
        {
            std::string name = element["name"].get<std::string>();
            bool expect_fail = element["expect-fail"].get<bool>();
            std::string result;
            std::string stoken = element["token"].get<std::string>();
            std::string footer = element["footer"].get<std::string>();
            std::string payload;

            std::cout << "Test: " <<  name;
            std::cout << "  expect-fail:" << expect_fail;

            if (element.contains("public-key"))
            {
                std::string spublic_key = element["public-key"].get<std::string>();
                std::string ssecret_key = element["secret-key"].get<std::string>();
                paseto::BinaryVector payload_bytes;
                if (!element["payload"].is_null())
                {
                    payload = element["payload"].get<std::string>();
                    payload_bytes = paseto::Binary::fromString(payload);
                }
                paseto::BinaryVector footer_bytes = 
                            paseto::Binary::fromString(footer);
                bool encryption_test_ok = false;

                auto seckey = paseto::Keys::createFromHex(
                        public_encode_keytype, ssecret_key);

                auto pubkey = paseto::Keys::createFromHex(
                        public_decode_keytype, spublic_key);

                try
                {
                    result = seckey->sign(payload_bytes, footer_bytes);
                }
                catch (std::exception &ex)
                {
                    // ignore for now
                }
                encryption_test_ok = (stoken == result);
                if (!result.empty())
                    std::cout << "  result:" << encryption_test_ok;
                else
                    std::cout << "  result:" << "null";
                if (encryption_test_ok || expect_fail)
                    std::cout << " signing:pass";
                else
                    std::cout << " signing;FAILED";

                paseto::Token token;
                try
                {
                    token = pubkey->verify(stoken);
                }
                catch (std::exception)
                {
                }

                if (!token.payload().empty())
                    std::cout << "  result:" << (token.payload() == payload_bytes);
                else
                    std::cout << "  result:" << "null";

                if ((!token.payload().empty() && payload_bytes == token.payload()) || expect_fail)
                    std::cout << " verify:pass";
                else
                    std::cout << " verify:FAILED";

                //std::cout << " result:" << (token.payload() == payload_bytes);
                std::cout << std::endl;
            }
            else
            {
                std::string skey = element["key"].get<std::string>();
                std::string nonce = element["nonce"].get<std::string>();

                // encryption test
                {
                    paseto::BinaryVector payload_bytes;
                    paseto::BinaryVector footer_bytes = 
                            paseto::Binary::fromString(footer);
                    bool encryption_test_ok = false;

                    if (!element["payload"].is_null())
                    {
                        payload = element["payload"].get<std::string>();
                        payload_bytes = paseto::Binary::fromString(payload);
                    }

                    std::unique_ptr<paseto::Key> key =
                            paseto::Keys::createFromHex(local_encode_keytype, skey);

                    if (nonce.length() == 2 * paseto_v2_LOCAL_NONCEBYTES)
                    {
                        key->setNonce(nonce, payload_bytes);

                        result = key->encrypt(payload_bytes, footer_bytes);

                        key->clearNonce();
                    }
                    encryption_test_ok = (stoken == result);
                    if (!result.empty())
                        std::cout << "  result:" << encryption_test_ok;
                    else
                        std::cout << "  result:" << "null";

                    if (encryption_test_ok || expect_fail)
                        std::cout << " encrypt:pass ";
                    else
                        std::cout << " encrypt:FAILED ";
                    result.clear();
                }

                // decryption test
                {
                    paseto::BinaryVector payload_bytes;
                    paseto::BinaryVector footer_bytes = paseto::Binary::fromString(footer);
                    bool decryption_test_ok = false;

                    if (!element["payload"].is_null())
                    {
                        payload = element["payload"].get<std::string>();
                        payload_bytes = paseto::Binary::fromString(payload);
                    }

                    auto key = paseto::Keys::createFromHex(
                         local_decode_keytype, skey);

                    paseto::Token token;
                    if (nonce.length() == 2 * paseto_v2_LOCAL_NONCEBYTES)
                    {
                        token = key->decrypt(stoken);
                    }
                
                    decryption_test_ok = (token.payload() == payload_bytes);
                    decryption_test_ok &= (token.footer() == footer_bytes);

                    if (!token.payload().empty())
                        std::cout << " result:" << decryption_test_ok;
                    else
                        std::cout << " result:" << "null";

                    if ((!token.payload().empty() && payload_bytes == token.payload()) || expect_fail)
                        std::cout << " decrypt:pass";
                    else
                        std::cout << " decrypt:FAILED";
                }

                std::cout << std::endl;
            }
        }
    }
    catch (std::exception &ex)
    {
        std::cout << std::endl << ex.what() << std::endl;
        std::cout << "caught an exception, continuing..." << std::endl;
    }
    return;
}
