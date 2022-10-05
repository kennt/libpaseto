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
    std::stringstream ostream;
    std::string seckey_hex;

    seckey_hex.reserve(2*paseto_v3_PUBLIC_SECRETKEYBYTES + 1);

    ostream << std::hex << std::noshowbase << sk.GetPrivateExponent();
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
    std::stringstream ostream;
    std::string pubkey_hex;
    const ECP::Point& q = pk.GetPublicElement();

    pubkey_hex.reserve(2*paseto_v3_PUBLIC_PUBLICKEYBYTES + 1);

    pubkey_hex.append(q.y.GetBit(0) ? "03" : "02");

    ostream << std::hex << std::noshowbase << q.x;
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
