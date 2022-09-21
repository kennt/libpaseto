// Implementation based on pyseto

extern "C" {
#include <sodium.h>
#include "paseto.h"
};

#include <cstring>
#include <exception>
#include <fmt/core.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include "scope_guard.hpp"

#include <iostream>


namespace paseto {

class BaseException : public std::exception
{
public:
    BaseException(const std::string s) : _message(s) {}
    const char * what() const throw()
    {
        return _message.c_str();
    }
private:
    std::string _message;
};

class UnexpectedException : public BaseException
{
public:
    UnexpectedException(const std::string s) : BaseException(s) {}
};

class LengthMismatchException : public BaseException
{
public:
    LengthMismatchException(const std::string s) : BaseException(s) {}
};

class InvalidKeyException : public BaseException
{
public:
    InvalidKeyException(const std::string s) : BaseException(s) {}
};

class UnsupportedException : public BaseException
{
public:
    UnsupportedException(const std::string s) : BaseException(s) {}
};



class BinaryView : public std::basic_string_view<uint8_t>
{
public:
    BinaryView()
    {}

    BinaryView(const uint8_t*p, size_t len)
        : std::basic_string_view<uint8_t>(p, len)
    {}

    static BinaryView fromString(const std::string s)
    {
        BinaryView bin_view(reinterpret_cast<const uint8_t *>(s.data()), s.length());
        return bin_view;        
    }
};

class BinaryVector : public std::vector<uint8_t>
{
public:
    operator BinaryView() const
    {
        return BinaryView(data(), size());
    }

    std::string_view toStringView() const
    {
        std::string_view sv(
            reinterpret_cast<char *>(const_cast<uint8_t *>(data())),
            size());
        return sv;
    }

    std::string toString()
    {
        std::string result;
        result.resize(this->size());
        memcpy(result.data(), this->data(), this->size()*sizeof(uint8_t));
        return result;
    }
};

class Binary
{
public:
    static BinaryVector fromHex(const std::string_view &s, size_t required_len=0)
    {
        BinaryVector vec;
        size_t bin_len;

        if (required_len)
            vec.resize(required_len*sizeof(uint8_t));
        else
            vec.resize((s.length())*sizeof(uint8_t)/2);

        int res = sodium_hex2bin(vec.data(), vec.size(),
                                s.data(), s.length(),
                                NULL, &bin_len, NULL);
        vec.resize(bin_len);
        if (res == -1)
            throw std::bad_alloc();
        else if (res)
            throw UnexpectedException("unexpected error from sodium_hex2bin");

        if (required_len && bin_len != required_len)
            throw LengthMismatchException("The required buffer is not the exact size");
        return vec;
    }

    static BinaryVector fromString(const std::string_view &s, size_t required_len=0)
    {
        BinaryVector vec;

        if (required_len && s.length() != required_len)
            throw LengthMismatchException("The required buffer is not the exact size");

        if (required_len)
            vec.resize(required_len*sizeof(uint8_t));
        else
            vec.resize(s.length()*sizeof(uint8_t));

        std::memcpy(vec.data(), s.data(), s.length()*sizeof(uint8_t));

        return vec;
    }

    static BinaryVector fromBase64(const std::string_view &s, size_t required_len=0)
    {
        BinaryVector vec;
        size_t bin_len;

        if (required_len)
            vec.resize(required_len*sizeof(uint8_t));
        else
            vec.resize((s.length()/4 * 3)*sizeof(uint8_t));

        int res = sodium_base642bin(vec.data(), vec.size(),
                                s.data(), s.length(),
                                NULL, &bin_len, NULL,
                                sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        vec.resize(bin_len);
        if (res == -1)
            throw std::bad_alloc();
        else if (res)
            throw UnexpectedException("unexpected error from sodium_hex2bin");
        if (required_len && bin_len != required_len)
            throw LengthMismatchException("The required buffer is not the exact size");
        return vec;
    }
    static BinaryVector fromData(const uint8_t *p, size_t len, size_t required_len=0)
    {
        BinaryVector vec;

        if (required_len && len != required_len)
            throw LengthMismatchException("The required buffer is not the exact size");

        if (required_len)
            vec.resize(required_len*sizeof(uint8_t));
        else
            vec.resize(len*sizeof(uint8_t));

        std::memcpy(vec.data(), p, len*sizeof(uint8_t));

        return vec;
    }
    static BinaryVector fromPem(const std::string s)
    {
        return BinaryVector();
    }

    inline static BinaryView none;
};

enum class KeyType : int {
    UNKNOWN = 0,

    V2_LOCAL = 21,
    V2_PUBLIC = 22,
    V2_SECRET = 23,

    V3_LOCAL = 31,
    V3_PUBLIC = 32,
    V3_SECRET = 33,

    V4_LOCAL = 41,
    V4_PUBLIC = 42,
    V4_SECRET = 43,
};

constexpr const char* KeyTypeToHeader(KeyType k) throw()
{
    switch (k)
    {
        case KeyType::UNKNOWN: return "unknown";
        case KeyType::V2_LOCAL: return "v2.local";
        case KeyType::V2_PUBLIC: return "v2.public";
        case KeyType::V2_SECRET: return "v2.secret";
        case KeyType::V3_LOCAL: return "v3.local";
        case KeyType::V3_PUBLIC: return "v3.public";
        case KeyType::V3_SECRET: return "v3.secret";
        case KeyType::V4_LOCAL: return "v4.local";
        case KeyType::V4_PUBLIC: return "v4.public";
        case KeyType::V4_SECRET: return "v4.secret";
        default: return "unknown";
    }
}

constexpr bool isKeyTypeLocal(KeyType k)
{
    return ((int)k % 10 == 1);
}

constexpr int KeyTypeVersion(KeyType k)
{
    return (int)k / 10;
}

class Token
{
public:
    Token()
    {
        _key_type = KeyType::UNKNOWN;
    }

    Token(KeyType key_type, uint8_t *payload, size_t payload_length,
        uint8_t *footer, size_t footer_len)
    : _key_type(key_type)
    {
        _payload = Binary::fromData(payload, payload_length);
        _footer = Binary::fromData(footer, footer_len);
    }

    std::string description()
    {
        return KeyTypeToHeader(_key_type);
    }
    BinaryVector header()
    {
        return Binary::fromString(description());
    }

    const BinaryVector &payload()
    {
        return _payload;
    }
    const BinaryVector &footer()
    {
        return _footer;
    }
private:
    KeyType _key_type;
    BinaryVector _payload;
    BinaryVector _footer;
};


class Key
{
public:
    std::string description()
    {
        return KeyTypeToHeader(_key_type);
    }
    BinaryVector header()
    {
        return Binary::fromString(description());
    }
    KeyType keyType() const
    {
        return _key_type;
    }
    void checkKey() const
    {
        if (!_is_loaded)
            throw InvalidKeyException("key has not been loaded");
        if (!paseto_init())
            throw UnexpectedException(
                fmt::format("paseto_init() failed errno:{}", errno));
    }
    //void toPaserk();
    //void toPaserkId();
    //void toPeerPaserkId();
    virtual std::string encrypt(const BinaryView &payload,
                 const BinaryView &footer = Binary::none,
                 const BinaryView &implicit_assertion = Binary::none) const
    {
        throw UnsupportedException("this must use a local key 1");
    }

    virtual Token decrypt(
                    const std::string_view &token,
                    const BinaryView &implicit_assertion = Binary::none) const
    {
        throw UnsupportedException("this must use a local key 2");
    }

    virtual std::string sign(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const
    {
        throw UnsupportedException("this must use a secret key");
    }

    virtual Token verify(
                    const std::string_view &token,
                    const BinaryView &implicit_assertion = Binary::none) const
    {
        throw UnsupportedException("this must use a public key");
    }

#ifdef DEBUG
    void setNonce(const std::string nonce_hex, const BinaryView &payload)
    {
        if (KeyTypeVersion(_key_type) == 2)
        {
            _saved_generate_nonce = generate_nonce;
            generate_nonce = nonce_override_generate_nonce; 

            uint8_t local_nonce[paseto_v2_LOCAL_NONCEBYTES];
            nonce_load_hex(local_nonce, nonce_hex.c_str());
            generate_reference_nonce(local_nonce,
                payload.data(), payload.size());
            nonce_override(local_nonce);
        }
        else if ((KeyTypeVersion(_key_type) == 3) ||
                 (KeyTypeVersion(_key_type) == 4))
        {
            _nonce = Binary::fromHex(nonce_hex);
            if (_nonce.size() != 32)
                throw std::invalid_argument("nonce");
        }
        else
            throw UnsupportedException("nonce not supported");

    }

    void clearNonce()
    {
        if (KeyTypeVersion(_key_type) == 2)
        {
            generate_nonce = _saved_generate_nonce;
        }
        _nonce.clear();
    }
private:
    generate_nonce_fn _saved_generate_nonce;
public:
#endif

    virtual ~Key() {}

protected:
    bool _is_loaded;
    BinaryVector _data;
    size_t _required_length;
    KeyType _key_type;

    BinaryVector _nonce;

private:
    friend class Keys;
};


template<enum KeyType key_type, size_t key_length, auto fencrypt, auto fdecrypt>
class LocalKey : public Key
{
public:
    LocalKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }
 
    // A base64 encoded string is returned
    std::string encrypt(const BinaryView &payload,
                    const BinaryView &footer = Binary::none,
                    const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        char * result = NULL;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          _data.data(),
                          footer.data(), footer.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        std::string s{result};
        return s;
    }

    Token decrypt(const std::string_view &token,
                  const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fdecrypt(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        return Token(_key_type, result, message_len, footer, footer_len);
    }
};


template<enum KeyType key_type, size_t key_length, auto fverify>
class PublicKey : public Key
{
public:
    PublicKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    Token verify(const std::string_view &token,
                 const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fverify(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        return Token(_key_type, result, message_len, footer, footer_len);
    }
};


template<enum KeyType key_type, size_t key_length, auto fsign>
class SecretKey : public Key
{
public:
    SecretKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string sign(const BinaryView &payload,
              const BinaryView &footer = Binary::none,
              const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        char * result = NULL;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fsign(payload.data(), payload.size(),
                       _data.data(),
                       footer.data(), footer.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        std::string s{result};
        return s;
    }
};

template<enum KeyType key_type, size_t key_length, auto fencrypt, auto fdecrypt>
class LocalKey2 : public Key
{
public:
    LocalKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }
 
    // A base64 encoded string is returned
    std::string encrypt(const BinaryView &payload,
                    const BinaryView &footer = Binary::none,
                    const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        char * result = NULL;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          _data.data(),
                          footer.data(), footer.size(),
                          implicit_assertion.data(), implicit_assertion.size(),
                          _nonce.data(), _nonce.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        std::string s{result};
        return s;
    }

    Token decrypt(const std::string_view &token,
                  const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fdecrypt(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len,
                          implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        return Token(_key_type, result, message_len, footer, footer_len);
    }
};


template<enum KeyType key_type, size_t key_length, auto fverify>
class PublicKey2 : public Key
{
public:
    PublicKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    Token verify(const std::string_view &token,
                 const BinaryView &implicit_assertion = Binary::none) const
    {
        checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fverify(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len,
                          implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        return Token(_key_type, result, message_len, footer, footer_len);
    }
};


template<enum KeyType key_type, size_t key_length, auto fsign>
class SecretKey2 : public Key
{
public:
    SecretKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string sign(const BinaryView &payload,
              const BinaryView &footer = Binary::none,
              const BinaryView &implicit_assertion = Binary::none) const
    {
        checkKey();

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fsign(payload.data(), payload.size(),
                       _data.data(),
                       footer.data(), footer.size(),
                       implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(std::strerror(errno));
        std::string s{result};
        return s;
    }
};


typedef LocalKey<KeyType::V2_LOCAL,
            paseto_v2_LOCAL_KEYBYTES,
            paseto_v2_local_encrypt,
            paseto_v2_local_decrypt> PasetoV2LocalKey;
typedef PublicKey<KeyType::V2_PUBLIC,
            paseto_v2_PUBLIC_PUBLICKEYBYTES,
            paseto_v2_public_verify> PasetoV2PublicKey;
typedef SecretKey<KeyType::V2_SECRET,
            paseto_v2_PUBLIC_SECRETKEYBYTES,
            paseto_v2_public_sign> PasetoV2SecretKey;

typedef LocalKey2<KeyType::V3_LOCAL,
            paseto_v3_LOCAL_KEYBYTES,
            paseto_v3_local_encrypt,
            paseto_v3_local_decrypt> PasetoV3LocalKey;
typedef PublicKey2<KeyType::V3_PUBLIC,
            paseto_v3_PUBLIC_PUBLICKEYBYTES,
            paseto_v3_public_verify> PasetoV3PublicKey;
typedef SecretKey2<KeyType::V3_SECRET,
            paseto_v3_PUBLIC_SECRETKEYBYTES,
            paseto_v3_public_sign> PasetoV3SecretKey;

#if 0
typedef LocalKey2<KeyType::V4_LOCAL,
            paseto_v4_LOCAL_KEYBYTES,
            paseto_v4_local_encrypt,
            paseto_v4_local_decrypt> PasetoV4LocalKey;
typedef PublicKey2<KeyType::V4_PUBLIC,
            paseto_v4_PUBLIC_PUBLICKEYBYTES,
            paseto_v4_public_verify> PasetoV4PublicKey;
typedef SecretKey2<KeyType::V4_SECRET,
            paseto_v4_PUBLIC_SECRETKEYBYTES,
            paseto_v4_public_sign> PasetoV4SecretKey;
#endif

class Keys
{
public:
    static std::unique_ptr<Key> create(KeyType type)
    {
        switch(type)
        {
            case KeyType::V2_LOCAL:
                return std::make_unique<PasetoV2LocalKey>();
            case KeyType::V2_PUBLIC:
                return std::make_unique<PasetoV2PublicKey>();
            case KeyType::V2_SECRET:
                return std::make_unique<PasetoV2SecretKey>();

            case KeyType::V3_LOCAL:
                return std::make_unique<PasetoV3LocalKey>();
            case KeyType::V3_PUBLIC:
                return std::make_unique<PasetoV3PublicKey>();
            case KeyType::V3_SECRET:
                return std::make_unique<PasetoV3SecretKey>();

#if 0
            case KeyType::V4_LOCAL:
                return std::make_unique<PasetoV4LocalKey>();
            case KeyType::V4_PUBLIC:
                return std::make_unique<PasetoV4PublicKey>();
            case KeyType::V4_SECRET:
                return std::make_unique<PasetoV4SecretKey>();
#endif
            default:
                throw InvalidKeyException(
                    fmt::format("Unsupported keytype: {}", (int) type));
        }
    }

    static std::unique_ptr<Key> createFromHex(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromHex(s, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> createFromBase64(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromBase64(s, key->_required_length);
        key->_is_loaded = true;
        return key;
    }
};


class Paseto
{
public:
    static std::string encode(const Key *key,
                        const BinaryView &payload,
                        const BinaryView &footer = Binary::none,
                        const BinaryView &implicit_assertion = Binary::none)
    {
        if (isKeyTypeLocal(key->keyType()))
            return key->encrypt(payload, footer, implicit_assertion);
        else
            return key->sign(payload, footer, implicit_assertion);
    }

    static Token decode(const Key *key,
                        const std::string &token,
                        const BinaryView &implicit_assertion = Binary::none)
    {
        if (isKeyTypeLocal(key->keyType()))
            return key->decrypt(token, implicit_assertion);
        else
            return key->verify(token, implicit_assertion);
    }

};


}; /* namespace:paseto */
