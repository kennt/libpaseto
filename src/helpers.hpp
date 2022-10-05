#ifndef INCLUDE_HELPERS_HPP
#define INCLUDE_HELPERS_HPP

#include <string>
#include <iostream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/algebra.h"
using CryptoPP::Integer;

#include "cryptopp/oids.h"

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA_RFC6979;

#include "cryptopp/sha.h"
using CryptoPP::SHA384;



std::string p384_privatekey_to_hex(ECDSA_RFC6979<ECP,SHA384>::PrivateKey &sk);

std::string p384_publickey_to_hex(ECDSA_RFC6979<ECP,SHA384>::PublicKey &pk);

#endif /* INCLUDE_HELPERS_HPP */
