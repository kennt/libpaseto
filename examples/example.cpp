
extern "C" {
#include "paseto.h"
};
#include "paseto.hpp"

#include <iostream>
#include <string>

using namespace std;

int main() {
    string message("test");
    string footer("footer");
    string key("jPGxsBcnjnruJJe3cF4dnjo1LVM-g8O6ktboqggzi2c");
    string encrypted;

    auto localkey = paseto::Keys::createFromBase64(
                        paseto::KeyType::V2_LOCAL, key);

    auto message_view = paseto::BinaryView::fromString(message);
    auto footer_view = paseto::BinaryView::fromString(footer);

    encrypted = localkey->encrypt(message_view);
    cout << "encrypted: " << encrypted << endl;

    encrypted = localkey->encrypt(message_view, footer_view);
    cout << "encrypted: " << encrypted << endl;

    auto token = localkey->decrypt(encrypted);
    cout << "decrypted: " << token.payload().toStringView() << endl;
    cout << "footer: " << token.footer().toStringView() << endl;
    return 0;
}
