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
std::string p384_privatekey_to_hex(const CryptoPP::Integer value);

std::string p384_publickey_to_hex(ECDSA_RFC6979<ECP,SHA384>::PublicKey &pk);
std::string p384_publickey_to_hex(const Integer &x, bool is_y);

void print_public_key_parameters(const char *title, const uint8_t *keydata, size_t keydatalen);
void print_private_key_parameters(const char *title, const uint8_t *keydata, size_t keydatalen);

void PrintDomainParameters( const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params );

#endif /* INCLUDE_HELPERS_HPP */