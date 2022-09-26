
#include "paseto.hpp"

#include <iostream>
#include <string>

using namespace std;

int main() {
    string message("test");
    string footer("footer");
    string keydata("jPGxsBcnjnruJJe3cF4dnjo1LVM-g8O6ktboqggzi2c");
    string encrypted;

    auto localkey = paseto::Keys::createFromBase64(
                        paseto::KeyType::V3_LOCAL, keydata);

    // Two different ways of doing the same thing
    // A BinaryView removes making a copy of the data
    paseto::BinaryView message_view {message};
    auto footer_view = paseto::BinaryView::fromString(footer);

    encrypted = localkey->encrypt(message_view, footer_view);
    cout << "encrypted: " << encrypted << endl;

    auto token = localkey->decrypt(encrypted);
    cout << "decrypted: " << token.payload().toStringView() << endl;
    cout << "footer: " << token.footer().toStringView() << endl;
    return 0;
}
