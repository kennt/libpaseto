extern "C" {
#include "paseto.h"
#include "paserk.h"
#include "helpers.h"
};

#include <filesystem>
#include <fstream>
#include <iostream>
using std::cout;
using std::endl;

#include <nlohmann/json.hpp>
#include <cstdio>
#include <set>

#include <fmt/core.h>
#include <fmt/color.h>

#define DEBUG
#include "paseto.hpp"

using json = nlohmann::json;
using namespace std;
namespace fs = std::filesystem;

void run_test_vector(const std::string &filename);

// Keep track of test status
set<std::string> failed_test_vectors;
int failed_test_count = 0;
int total_test_count = 0;

int main(int argc, char **argv)
{
    set<fs::path> file_list;

    for (auto &entry : fs::directory_iterator("./test/paserk"))
        file_list.insert(entry.path().filename().string());
    
    for (const auto &filename : file_list)
    {
        run_test_vector(filename.string());
    }

    cout << "Summary results ----------------" << endl;
    cout << failed_test_count << " of " << total_test_count << " tests failed" << endl;
    for (const auto& name : failed_test_vectors)
    {
        cout << "  " << name << endl;
    }

    return 0;
}

paseto::KeyType KeyTypeForTest(const string &version, const string &test_type)
{
    if (version == "k2")
    {
        if (test_type == "lid" ||
            test_type == "local-pw" ||
            test_type == "local-wrap" ||
            test_type == "local" ||
            test_type == "seal"
            )
            return paseto::KeyType::V2_LOCAL;
        else if (test_type == "pid" ||
                 test_type == "public")
            return paseto::KeyType::V2_PUBLIC;
        else if (test_type == "sid" ||
                 test_type == "secret" ||
                 test_type == "secret-pw" ||
                 test_type == "secret-wrap.pie"
                )
            return paseto::KeyType::V2_SECRET;
        else
            throw paseto::UnsupportedException("unknown keytype");
    }
    else if (version == "k3")
    {
        if (test_type == "lid" ||
            test_type == "local-pw" ||
            test_type == "local-wrap" ||
            test_type == "local" ||
            test_type == "seal"
            )
            return paseto::KeyType::V3_LOCAL;
        else if (test_type == "pid" ||
                 test_type == "public")
            return paseto::KeyType::V3_PUBLIC;
        else if (test_type == "sid" ||
                 test_type == "secret" ||
                 test_type == "secret-pw" ||
                 test_type == "secret-wrap.pie"
                )
            return paseto::KeyType::V3_SECRET;
        else
            throw paseto::UnsupportedException("unknown keytype");
    }
    else if (version == "k4")
    {
        if (test_type == "lid" ||
            test_type == "local-pw" ||
            test_type == "local-wrap" ||
            test_type == "local" ||
            test_type == "seal"
            )
            return paseto::KeyType::V4_LOCAL;
        else if (test_type == "pid" ||
                 test_type == "public")
            return paseto::KeyType::V4_PUBLIC;
        else if (test_type == "sid" ||
                 test_type == "secret" ||
                 test_type == "secret-pw" ||
                 test_type == "secret-wrap.pie"
                )
            return paseto::KeyType::V4_SECRET;
        else
            throw paseto::UnsupportedException("unknown keytype");
    }
    else
        throw paseto::UnsupportedException("unknown version");
}

typedef  std::string (paseto::Key::*FNTO_PASERK_NO_PARAMS)();
typedef  std::string (paseto::Key::*FNTO_PASERK_SECRET)(const paseto::BinaryView &);

typedef  void (paseto::Key::*FNFROM_PASERK)(const std::string &);


// For simple tests that take no parameters (local, global secret)
void run_no_params_test_vector(json &j,
    const std::string &version,
    const std::string &sKeyType,
    FNTO_PASERK_NO_PARAMS fEncodePaserk,
    FNFROM_PASERK fDecodePaserk)
{
    try
    {
        paseto::KeyType keytype = KeyTypeForTest(version, sKeyType);
        for (const auto& element : j["tests"])
        {
            total_test_count ++;

            string name = element["name"].get<string>();
            bool expect_fail = element["expect-fail"].get<bool>();
            string key;
            if (!element["key"].is_null())
                key = element["key"].get<string>();
            string paserk;
            if (!element["paserk"].is_null())
                paserk = element["paserk"].get<string>();
            bool test_ok = true;

            cout << name << " " << "expect-fail:" << expect_fail;

            std::string actual;

            try
            {
                std::unique_ptr<paseto::Key> paserk_key;
                paserk_key = paseto::Keys::createFromHex(keytype, key);
                actual = ((paserk_key.get())->*fEncodePaserk)();
                test_ok = (actual == paserk);
            }
            catch (exception ex)
            {
                test_ok = false;
            }

            if (test_ok == expect_fail)
            {
                failed_test_count ++;
                failed_test_vectors.insert(name);
                cout << endl;
                cout << "actual : " << actual.length() << " : " << actual << endl;
                cout << "expect : " << paserk.length() << " : " << paserk << endl;
            }

            if (test_ok != expect_fail)
                cout << "  encode: pass";
            else
                cout << "  encode: FAILED";


            if (fDecodePaserk)
            {
                // take 'paserk' and see if generates the 'key'
                std::string paserk_hex;
                try
                {
                    test_ok = true;

                    std::unique_ptr<paseto::Key> paserk_key = paseto::Keys::create(keytype);
                    ((paserk_key.get())->*fDecodePaserk)(element["paserk"].get<std::string>());

                    std::string paserk_hex = paserk_key->toHex();
                    test_ok = (paserk_hex == key);
                }
                catch (exception ex)
                {
                    test_ok = false;
                    if (!expect_fail)
                    {
                        cout << endl << ex.what() << endl;
                        //cout << "caught an exception, continuing..." << endl;
                    }
                }
                if (test_ok == expect_fail)
                {
                    failed_test_count ++;
                    failed_test_vectors.insert(name);
                    if (!expect_fail)
                    {
                        cout << endl;
                        cout << "actual : " << paserk_hex.length() << " : " << paserk_hex << endl;
                        cout << "expect : " << key.length() << " : " << key << endl;
                    }
                }

                if (test_ok != expect_fail)
                    cout << "  decode: pass";
                else
                    cout << "  decode: FAILED";
            }
            cout << endl;
        }
    }
    catch (exception &ex)
    {
        cout << endl << ex.what() << endl;
        cout << "caught an exception, continuing..." << endl;
    }    
}

void run_lid_test_vector(json &j, std::string version)
{
    // create function object to call toPaserkId()
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserkId;
    run_no_params_test_vector(j, version, "local", fEncode, nullptr);
}

void run_local_pw_test_vector(json &j, std::string version)
{
}

void run_local_wrap_pie_test_vector(json &j, std::string version, const std::string &sKeyType)
{
    try
    {
        paseto::KeyType keytype = KeyTypeForTest(version, sKeyType);
        for (const auto& element : j["tests"])
        {
            total_test_count ++;

            string name = element["name"].get<string>();
            bool expect_fail = element["expect-fail"].get<bool>();
            string unwrapped;
            if (!element["unwrapped"].is_null())
                unwrapped = element["unwrapped"].get<string>();
            string paserk;
            if (!element["paserk"].is_null())
                paserk = element["paserk"].get<string>();
            string wrapping_key = element["wrapping-key"].get<string>();
            paseto::BinaryVector wk_bin = paseto::Binary::fromHex(wrapping_key);
            bool test_ok = true;

            // We really can't test sealing (since it uses an ephemeral pk/sk)
            // So we can only test unsealing (with the test data)
            // (but will also test sealing/unsealing ourselves)

            cout << name << " " << "expect-fail:" << expect_fail;

            if (!expect_fail)
            {
                test_ok = true;
                // self-test
                // seal and unseal
                std::string actual;
                std::unique_ptr<paseto::Key> paserk_key;
                std::unique_ptr<paseto::Key> unsealed_key;

                paserk_key = paseto::Keys::createFromHex(keytype, unwrapped);

                // copies paserk_key to a wrap
                actual = paserk_key->toPaserkWrap(wk_bin);

                // convert back into a key
                unsealed_key = paseto::Keys::create(keytype);
                unsealed_key->fromPaserkWrap(actual, wk_bin);

                // this should be the same as paserk_key
                if (*paserk_key == *unsealed_key)
                    cout << "  self-test:pass";
                else
                {
                    test_ok = false;
                    cout << "  self-test:FAILED";
                }
            }

            std::string actual;

            {
                std::string paserk_hex;
                try
                {
                    test_ok = true;

                    std::unique_ptr<paseto::Key> paserk_key = paseto::Keys::create(keytype);
                    paserk_key->fromPaserkWrap(element["paserk"].get<std::string>(), wk_bin);

                    std::string paserk_hex = paserk_key->toHex();
                    test_ok = (paserk_hex == unwrapped);
                }
                catch (exception ex)
                {
                    test_ok = false;
                    if (!expect_fail)
                    {
                        cout << endl << ex.what() << endl;
                        //cout << "caught an exception, continuing..." << endl;
                    }
                }
                if (test_ok == expect_fail)
                {
                    failed_test_count ++;
                    failed_test_vectors.insert(name);
                    if (!expect_fail)
                    {
                        cout << endl;
                        cout << "actual : " << paserk_hex.length() << " : " << paserk_hex << endl;
                        cout << "expect : " << unwrapped.length() << " : " << unwrapped << endl;
                    }   
                }

                if (test_ok != expect_fail)
                    cout << "  decode: pass";
                else
                    cout << "  decode: FAILED";
            }
            cout << endl;
        }
    }
    catch (exception &ex)
    {
        cout << endl << ex.what() << endl;
        cout << "caught an exception, continuing..." << endl;
    }
}

void run_local_test_vector(json &j, std::string version)
{
    // create function object to call toPaserk()
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserk;
    FNFROM_PASERK fDecode = &paseto::Key::fromPaserk;
    run_no_params_test_vector(j, version, "local", fEncode, fDecode);
}

void run_pid_test_vector(json &j, std::string version)
{
    // create function object to call toPaserkId()
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserkId;
    run_no_params_test_vector(j, version, "public", fEncode, nullptr);
}

void run_public_test_vector(json &j, std::string version)
{
    // create function object to call toPaserk()
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserk;
    FNFROM_PASERK fDecode = &paseto::Key::fromPaserk;
    run_no_params_test_vector(j, version, "public", fEncode, fDecode);
}

void run_seal_test_vector(json &j, std::string version, const std::string &sKeyType)
{
    try
    {
        paseto::KeyType keytype = KeyTypeForTest(version, sKeyType);
        for (const auto& element : j["tests"])
        {
            total_test_count ++;

            string name = element["name"].get<string>();
            bool expect_fail = element["expect-fail"].get<bool>();
            string unsealed;
            if (!element["unsealed"].is_null())
                unsealed = element["unsealed"].get<string>();
            string paserk;
            if (!element["paserk"].is_null())
                paserk = element["paserk"].get<string>();
            string sealing_secret_key = element["sealing-secret-key"].get<string>();
            string sealing_public_key = element["sealing-public-key"].get<string>();
            paseto::BinaryVector pk_bin = paseto::Binary::fromHex(sealing_public_key);
            paseto::BinaryVector sk_bin = paseto::Binary::fromHex(sealing_secret_key);
            bool test_ok = true;

            // We really can't test sealing (since it uses an ephemeral pk/sk)
            // So we can only test unsealing (with the test data)
            // (but will also test sealing/unsealing ourselves)

            cout << name << " " << "expect-fail:" << expect_fail;

            if (!expect_fail)
            {
                test_ok = true;
                // self-test
                // seal and unseal
                std::string actual;
                std::unique_ptr<paseto::Key> paserk_key;
                std::unique_ptr<paseto::Key> unsealed_key;

                paserk_key = paseto::Keys::createFromHex(keytype, unsealed);

                // copies paserk_key to a seal
                actual = paserk_key->toPaserkSeal(pk_bin);

                // convert back into a key
                unsealed_key = paseto::Keys::create(keytype);
                unsealed_key->fromPaserkSeal(actual, sk_bin);

                // this should be the same as paserk_key
                if (*paserk_key == *unsealed_key)
                    cout << "  self-test:pass";
                else
                {
                    test_ok = false;
                    cout << "  self-test:FAILED";
                }
            }

            std::string actual;

            {
                std::string paserk_hex;
                try
                {
                    test_ok = true;

                    std::unique_ptr<paseto::Key> paserk_key = paseto::Keys::create(keytype);
                    paserk_key->fromPaserkSeal(element["paserk"].get<std::string>(), sk_bin);

                    std::string paserk_hex = paserk_key->toHex();
                    test_ok = (paserk_hex == unsealed);
                }
                catch (exception ex)
                {
                    test_ok = false;
                    if (!expect_fail)
                    {
                        cout << endl << ex.what() << endl;
                        //cout << "caught an exception, continuing..." << endl;
                    }
                }
                if (test_ok == expect_fail)
                {
                    failed_test_count ++;
                    failed_test_vectors.insert(name);
                    if (!expect_fail)
                    {
                        cout << endl;
                        cout << "actual : " << paserk_hex.length() << " : " << paserk_hex << endl;
                        cout << "expect : " << unsealed.length() << " : " << unsealed << endl;
                    }
                }

                if (test_ok != expect_fail)
                    cout << "  decode: pass";
                else
                    cout << "  decode: FAILED";
            }
            cout << endl;
        }
    }
    catch (exception &ex)
    {
        cout << endl << ex.what() << endl;
        cout << "caught an exception, continuing..." << endl;
    }
}

void run_secret_pw_test_vector(json &j, std::string version)
{
}

void run_secret_wrap_pie_test_vector(json &j, std::string version)
{
    run_local_wrap_pie_test_vector(j, version, "secret");
}

void run_secret_test_vector(json &j, std::string version)
{
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserk;
    FNFROM_PASERK fDecode = &paseto::Key::fromPaserk;
    run_no_params_test_vector(j, version, "secret", fEncode, fDecode);
}

void run_sid_test_vector(json &j, std::string version)
{
    // create function object to call toPaserkId()
    FNTO_PASERK_NO_PARAMS fEncode = &paseto::Key::toPaserkId;
    run_no_params_test_vector(j, version, "secret", fEncode, nullptr);
}


void run_test_vector(const std::string &filename)
{
    paseto_init();

    string version = filename.substr(0,2);
    string test_type = filename.substr(3, filename.length()-8);

    if (version == "k1")
    {
        cout << filename << ": skipping" << endl;
        return;
    }

    string path = "test/paserk/";
    json j;

    // v2
    assert(filesystem::exists(path + filename));
    ifstream fstream(path + filename);
    j = json::parse(fstream);
    cout << "----------------------------------------" << endl;
    cout << "File: " << filename << "  Name: " << j["name"] << endl;

    if (test_type == "lid") run_lid_test_vector(j, version);
    else if (test_type == "local-pw") run_local_pw_test_vector(j, version);
    else if (test_type == "local-wrap.pie") run_local_wrap_pie_test_vector(j, version, "local");
    else if (test_type == "local") run_local_test_vector(j, version);
    else if (test_type == "pid") run_pid_test_vector(j, version);
    else if (test_type == "public") run_public_test_vector(j, version);
    else if (test_type == "seal") run_seal_test_vector(j, version, "local");
    else if (test_type == "secret-pw") run_secret_pw_test_vector(j, version);
    else if (test_type == "secret-wrap.pie") run_secret_wrap_pie_test_vector(j, version);
    else if (test_type == "secret") run_secret_test_vector(j, version);
    else if (test_type == "sid") run_sid_test_vector(j, version);
    else
        cout << "Unknown test type! : " << filename << " : " << endl;
    return;
}
