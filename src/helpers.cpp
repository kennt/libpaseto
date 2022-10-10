extern "C" {
#include "paseto.h"
#include "paserk.h"
#include <sodium.h>
};

#include <string>
#include <iostream>
#include <sstream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/algebra.h"
using CryptoPP::Integer;

#include "cryptopp/oids.h"

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA_RFC6979;

#include "cryptopp/sha.h"
using CryptoPP::SHA384;

#include "helpers.hpp"

std::string p384_privatekey_to_hex(CryptoPP::ECDSA_RFC6979<ECP,SHA384>::PrivateKey &sk)
{
    return p384_privatekey_to_hex(sk.GetPrivateExponent());
}

std::string p384_privatekey_to_hex(const CryptoPP::Integer value)
{
    std::stringstream ostream;
    std::string seckey_hex;

    seckey_hex.reserve(2*paseto_v3_PUBLIC_SECRETKEYBYTES + 1);

    ostream << std::hex << std::noshowbase << value;
    seckey_hex.append(ostream.str());
    seckey_hex.resize(seckey_hex.length()-1);   // remove 'h' at the end
    std::stringstream().swap(ostream);

    /* ensure that we are zero-filled on the left */
    ostream.width(2*paseto_v3_PUBLIC_SECRETKEYBYTES);
    ostream.fill('0');
    ostream << seckey_hex;
    seckey_hex = ostream.str();
    std::stringstream().swap(ostream);

    return seckey_hex;
}

std::string p384_publickey_to_hex(ECDSA_RFC6979<ECP,SHA384>::PublicKey &pk)
{
    const ECP::Point& q = pk.GetPublicElement();
    return p384_publickey_to_hex(q.x, q.y.GetBit(0));
}

std::string p384_publickey_to_hex(const Integer &x, bool is_y)
{
    std::stringstream ostream;
    std::string pubkey_hex;

    pubkey_hex.reserve(2*paseto_v3_PUBLIC_PUBLICKEYBYTES + 1);

    pubkey_hex.append(is_y ? "03" : "02");

    ostream << std::hex << std::noshowbase << x;
    std::string pubkey_data = ostream.str();
    pubkey_data.resize(pubkey_data.length()-1);   // remove 'h' at the end
    std::stringstream().swap(ostream);  // reset ostream

    /* ensure that we are zero-filled on the left */
    ostream.width(2*paseto_v3_PUBLIC_PUBLICKEYBYTES-2);
    ostream.fill('0');
    ostream << pubkey_data;
    pubkey_hex.append(ostream.str());

    return pubkey_hex;
}

void PrintDomainParameters( const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params )
{
    std::cout << "Modulus:" << std::endl;
    std::cout << " " << params.GetCurve().GetField().GetModulus() << std::endl;
    std::cout << "Coefficient A:" << std::endl;
    std::cout << " " << params.GetCurve().GetA() << std::endl;
    std::cout << "Coefficient B:" << std::endl;
    std::cout << " " << params.GetCurve().GetB() << std::endl;
    std::cout << "Base Point:" << std::endl;
    std::cout << " X: " << params.GetSubgroupGenerator().x << std::endl;
    std::cout << " Y: " << params.GetSubgroupGenerator().y << std::endl;
    std::cout << "Subgroup Order:" << std::endl;
    std::cout << " " << params.GetSubgroupOrder() << std::endl;
    std::cout << "Cofactor:" << std::endl;
    std::cout << " " << params.GetCofactor() << std::endl;
}


void print_public_key_parameters(const char *title, const uint8_t *keydata, size_t keydatalen)
{
    // Load the data into a key
    CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> public_key;
    ECP::Point point;

    public_key.AccessGroupParameters().Initialize(CryptoPP::ASN1::secp384r1());
    public_key.GetGroupParameters().GetCurve().DecodePoint (point, keydata, keydatalen);
    public_key.SetPublicElement(point);

    std::cout << title << std::endl;
    PrintDomainParameters(public_key.GetGroupParameters());
}

void print_private_key_parameters(const char *title, const uint8_t *keydata, size_t keydatalen)
{
    // Load the data into a key
    CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> secret_key;
    Integer x {keydata, keydatalen};
    secret_key.Initialize(CryptoPP::ASN1::secp384r1(), x);

    std::cout << title << std::endl;
    PrintDomainParameters(secret_key.GetGroupParameters());
}
