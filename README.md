# C/C++ library for Paseto
This is a work-in-progress.

Additions:
- v3/v4 implementations (with a C interface)
- A C++ header-only interface for versions 2/3/4
- an additional test executable that runs through the json test vectors
- a Dockerfile to use for building
- a Makefile to help with the Docker builds

Restrictions:
- The C++ code relies on C++ 17.

```
  # Builds the docker image used for the build system
  make build-docker-image

  # Startup the docker container
  make start

  # Runs the cmake build
  make build

  # Runs the test progams as well as the unit tests
  make test

  # Stop the docker container
  make stop

  # Removes the build directory
  make clean
```


```
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
    // A BinaryView removes the need to copy the data
    paseto::BinaryView message_view {message};
    auto footer_view = paseto::BinaryView::fromString(footer);

    encrypted = localkey->encrypt(message_view, footer_view);
    cout << "encrypted: " << encrypted << endl;

    auto token = localkey->decrypt(encrypted);
    cout << "decrypted: " << token.payload().toStringView() << endl;
    cout << "footer: " << token.footer().toStringView() << endl;
    return 0;
}
```

# C library for PASETO
*libpaseto* is a low-level implementation of
[Platform-Agnostic Security Tokens](https://paseto.io/) in C.
It only supports v2 public and private tokens, v1 is not supported. PASETO
Registered Claims are not in the scope of this project but can be built ontop
of *libpaseto*.

## Building
*libpaseto* only depends on [libsodium](https://libsodium.org/) and uses CMake.
It can be built using the following commands:

```
mkdir build
cd build
cmake ..
make
cd ..
build/pasetotest
```

## Usage overview
- Initialize the library: `paseto_init`
- Load a key using `paseto_v2_{local,public}_load_...`
- Encrypt or sign a message using `paseto_v2_local_encrypt` or
  `paseto_v2_public_sign` respectively
- Decrypt or verify a token using `paseto_v2_local_decrypt` or
  `paseto_v2_public_verify` respectively. They will return the decoded message
  on success, a null pointer otherwise.
- Clean up returned results using `paseto_free`

Refer to [example.c](examples/example.c) for a detailed example.

## License
libpaseto is published under the [3-clause BSD license](LICENSE) and makes use
of libsodium which is published under the [ISC license](libsodium.LICENSE).
