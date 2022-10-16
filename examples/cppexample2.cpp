
#include "paseto.hpp"

#include <iostream>
using std::cout;
using std::endl;

#include <sstream>
#include <string>
using std::string;

#include <cassert>
#include <cstring>

int main() {

    // --------------------------------------------------------
    // Paseto local-key (symmetric) encryption
    //
    // Underlying key data are generated by the libsodium
    // random number generator.
    //
    // The footer data is optional.
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);

        string data {"test data"};
        string footer {"footer data"};

        string encrypted_data = local_key->encrypt(data, footer);
        paseto::Token token = local_key->decrypt(encrypted_data);

        assert( token.payload().toString() == data );
        assert( token.footer().toString() == footer );
    }


    // --------------------------------------------------------
    // Paseto public/private (asymmetric) signing
    //
    // Underlying keys are generated by the associated library:
    // either libsodium (Ed25519) or crypto++ (P-384)
    {
        auto [ public_key, secret_key ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

        string data {"test data"};

        string signed_data = secret_key->sign(data);
        paseto::Token verified_token = public_key->verify(signed_data);

        assert( verified_token.payload().toString() == data );
    }


    // --------------------------------------------------------
    // Implicit assertions
    // Versions 3 and up include support for implicit assertions
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);

        string data {"test data"};
        string implicit_assertion {"my-implicit-data"};

        string encrypted_data = local_key->encrypt(data,
                paseto::binary::none /* optional footer */,
                implicit_assertion);
        paseto::Token token = local_key->decrypt(encrypted_data,
                implicit_assertion);

        assert( token.payload().toString() == data );
    }


    // --------------------------------------------------------
    // Paseto key generation
    //
    // Keys may be loaded directly from a piece of data or
    // may be generated.
    //
    // Loading paseto keys
    //  bin
    //  hex
    //  base64
    //  pem (V3_PUBLIC and V3_SECRET only)
    {
        {
            uint8_t binary_data[paseto_v3_LOCAL_KEYBYTES];
            randombytes_buf(binary_data, sizeof(binary_data));

            auto key = paseto::Keys::loadFromBinary(
                    paseto::KeyType::V3_LOCAL,
                    paseto::binary_view(binary_data, sizeof(binary_data)));
        }

        {
            string hex_data = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

            auto key = paseto::Keys::loadFromHex(
                    paseto::KeyType::V3_LOCAL, hex_data);
        }

        {
            string base64_data = "O6CSZr_riQS9lxGnUUkKlHu-VxVtJbMh1QVyOCJw3J0";

            auto key = paseto::Keys::loadFromBase64(
                    paseto::KeyType::V3_LOCAL, base64_data);
        }

        {
            string pem_secret = "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L\nJpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb\nTzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE\nzjhi6u4sNgzW23rrVkRYkb2oE3SJPko=\n-----END EC PRIVATE KEY-----";
            string pem_public = "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ\nW08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio\nhM44YuruLDYM1tt661ZEWJG9qBN0iT5K\n-----END PUBLIC KEY-----";

            auto public_key = paseto::Keys::loadFromPem(
                                paseto::KeyType::V3_PUBLIC, pem_public);
            auto secret_key = paseto::Keys::loadFromPem(
                                paseto::KeyType::V3_SECRET, pem_secret);
        }
    }


    // --------------------------------------------------------
    // PASERK (Platform-Agnostic Serializec Keys) is an extension
    // to Paseto that provides key-wrapping and serialization.
    //

    // --------------------------------------------------------
    // Paserk Id
    // Returns a representation of the key
    //
    // Available for all keys (LOCAL/PUBLIC/SECRET)
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto [ public_key, secret_key ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

        // examples (results will differ due to randomly generated keys)
        // local:  k3.lid.sbAsSN91MqA-vBMnAVxHea2v9DnDTJawQrrhMt4FjmNW
        cout << "local:  " << local_key->paserkId() << endl;

        // public: k3.pid.Nk1YuybnNQ1cqO1HHqZXnzA3Ol1OlhCS6m0DqqOtee2S
        cout << "public: " << public_key->paserkId() << endl;

        // secret: k3.sid.pmn5H0GjKhN1exzC4jPCfeFZv3ypUUqe5bW4-3h4xkx8
        cout << "secret: " << secret_key->paserkId() << endl;
    }

    // --------------------------------------------------------
    // Paserk key
    // Serializes the key (unencrypted)
    //
    // Available for all keys (LOCAL/PUBLIC/SECRET)
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto [ public_key, secret_key ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

        // examples (results will differ due to randomly generated keys)
        // local:  k3.local.dKxKp1sAkw9nmAM5Za3JdhgAbbq6WKMs-j6E-j4PpKE
        auto paserk_local = local_key->toPaserk();
        cout << "local:  " << paserk_local << endl;

        // public: k3.public.Axy_R7fdmvjCDfpi658FUfiKXAPHGV_8ZgK6X3f1aHnr2GrSGFYbX4S10zwsor_FBw
        auto paserk_public = public_key->toPaserk();
        cout << "public: " << paserk_public << endl;

        // secret: k3.secret.tEpPwkfI7uuxm79KqBewQ8sBgi6LoyXTXgNWZNZUkINVSvWv-my2OCLD9ARA9PZ2
        auto paserk_secret = secret_key->toPaserk();
        cout << "secret: " << paserk_secret << endl;


        // restore the keys
        // the key must match the original version and purpose

        // paseto::Keys::create() will create an empty key
        auto restored_key = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        restored_key->fromPaserk(paserk_local);

        restored_key = paseto::Keys::create(paseto::KeyType::V3_PUBLIC);
        restored_key->fromPaserk(paserk_public);

        restored_key = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        restored_key->fromPaserk(paserk_secret);
    }

    // --------------------------------------------------------
    // Paserk seal
    // Symmetric key wrapped by Asymmetric encryption
    //
    // Available for LOCAL keys using PUBLIC/SECRET keys
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto [ public_key, secret_key ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

        // seal the key with the public-key
        string sealed_data = local_key->paserkSeal(public_key.get());

        // sealed: k3.seal.YEH1wZPVAVvKTEgGg9soR-0a7elSPed44MpOFEa5ncGiwCOwcLx4swWj_cZQnorBA1wr6QIIzl25sbTIyPQcLeAVQRSMzEHV4mHEGHy-GxrUfyPrRJKnjhmrt2TWn3IaBycD47CPuxbZu3K19DPYHMKBrlYH05DuAo1Qb2sJILQO
        cout << "sealed: " << sealed_data << endl;

        // unseal the key with the secret-key
        auto restored_key = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        restored_key->paserkUnseal(sealed_data, secret_key.get());

        assert( restored_key->is_loaded() );
        assert( *local_key == *restored_key );
    }

    // --------------------------------------------------------
    // Paserk wrap
    // Key wrapped by Symmetric encryption
    //
    // Available for LOCAL/SECRET keys using LOCAL keys
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);
        auto [ public_key, secret_key ] =
            paseto::KeyGen::generatePair(paseto::KeyType::V3_PUBLIC);

        // Wrap a secret-key (could also be a local-key)
        string wrapped_data = secret_key->paserkWrap(local_key.get());

        // wrapped: k3.secret-wrap.pie.vNKrbBYNpnSnXKVfgy3JYV0pMjGt8ubqJAYBwPs9jH9__X5LcXADo4q-66sDaKXbRagqns8TD-FuBN3U-P-3E6CFI1ADbzfW51mfKDnayqJnP5ep_JVT6DrBqgoACUW3UFV9NX9RcVlIRALAqpqOJ8pOQT8IEkiZCJ75Oyo3DDA
        cout << "wrapped: " << wrapped_data << endl;

        // Unwrap the key using the local key
        auto restored_key = paseto::Keys::create(paseto::KeyType::V3_SECRET);
        restored_key->paserkUnwrap(wrapped_data, local_key.get());

        assert( *secret_key == *restored_key );
    }

    // --------------------------------------------------------
    // Paserk password wrap
    // Key wrapped by a password
    //
    // Available for LOCAL/SECRET keys using a password
    {
        std::unique_ptr<paseto::Key> local_key =
            paseto::KeyGen::generate(paseto::KeyType::V3_LOCAL);

        struct paseto::PasswordParams opts;
        opts.params.v3.iterations = 25000;

        // wrap the key with a password
        auto pw_dsta = local_key->paserkPasswordWrap("test-pass", &opts);

        // password-wrapped: k3.local-pw.QsYDWkV-viv6ASvOEM8VHsjz9BGckOlSVWW__KkbbOUAAGGo2RrxpzEoV6J5Ng49ow9uq_3id6aA5eCs1c0-VC-FwoT6MYundSQKVq6GUiFwonamCLQiLVbw6OxCqy5p-N5TshN59p6dfaJRPZxNyyamsu2kag5DqDMP9VDpDsLRYewD
        cout << "password-wrapped: " << pw_dsta << endl;

        // restore the key from the password-wrapped key
        auto restored_key = paseto::Keys::create(paseto::KeyType::V3_LOCAL);
        restored_key->paserkPasswordUnwrap(pw_dsta, "test-pass");

        assert( *local_key == *restored_key );
    }

    return 0;
}
