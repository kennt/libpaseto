// Implementation based on pyseto

#ifndef INCLUDE_PASETO_HPP
#define INCLUDE_PASETO_HPP

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
#include <utility>
#include <vector>

#include <iostream>

namespace paseto {

//
// https://codereview.stackexchange.com/questions/134234/on-the-fly-destructors
//
template<class F>
auto on_scope_exit( F&& f )
    noexcept( std::is_nothrow_move_constructible<F>::value )
{
    class unique_scope_exit_t final
    {
        F f_;

    public:
        ~unique_scope_exit_t()
            noexcept( noexcept( f_() ) )
        {
            f_();
        }

        explicit unique_scope_exit_t( F&& f )
            noexcept( std::is_nothrow_move_constructible<F>::value )
            : f_( std::move( f ) )
        {}

        unique_scope_exit_t( unique_scope_exit_t&& rhs )
            noexcept( std::is_nothrow_move_constructible<F>::value )
            : f_{ std::move( rhs.f_ ) }
        {}

        unique_scope_exit_t( unique_scope_exit_t const& ) = delete;
        unique_scope_exit_t& operator=( unique_scope_exit_t const& ) = delete;
        unique_scope_exit_t& operator=( unique_scope_exit_t&& ) = delete;
    };
    return unique_scope_exit_t{ std::move( f ) };
};



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

    BinaryView(const std::string_view &sv)
        : std::basic_string_view<uint8_t>(
            reinterpret_cast<const uint8_t *>(sv.data()), sv.length())
    {}

    static BinaryView fromString(const std::string_view s)
    {
        BinaryView bin_view(s);
        return bin_view;        
    }

    std::string toHex() const
    {
        std::string result;
        result.resize(2*this->size()+1);
        sodium_bin2hex(result.data(), result.length(), this->data(), this->size());
        result.resize(2*this->size());
        return result;
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

    std::string toString() const
    {
        std::string result;
        result.resize(this->size());
        memcpy(result.data(), this->data(), this->size()*sizeof(uint8_t));
        return result;
    }

    std::string toHex() const
    {
        std::string result;
        result.resize(2*this->size()+1);
        sodium_bin2hex(result.data(), result.length(), this->data(), this->size());
        result.resize(2*this->size());
        return result;
    }

    void appendHex(const std::string s)
    {
        size_t orig_size = this->size();
        size_t added_size = s.length()/2;
        size_t bin_len;

        this->resize(orig_size + added_size);
        int res = sodium_hex2bin(this->data()+orig_size, added_size,
                                s.data(), s.length(),
                                NULL, &bin_len, NULL);
        if (res == -1)
            throw std::bad_alloc();
        else if (res)
            throw UnexpectedException(
                fmt::format("Unexpected: sodium_hex2bin error (line {})", __LINE__));

        this->resize(orig_size+bin_len);
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
            throw UnexpectedException(
                fmt::format("Unexpected: sodium_hex2bin error (line {})", __LINE__));

        if (required_len && bin_len != required_len)
            throw LengthMismatchException(
                fmt::format("LengthMismatch: Incorrect size: required:{} actual:{} (line {})",
                    required_len, bin_len, __LINE__));
        return vec;
    }

    static BinaryVector fromString(const std::string_view &s, size_t required_len=0)
    {
        BinaryVector vec;

        if (required_len && s.length() != required_len)
            throw LengthMismatchException(
                fmt::format("LengthMismatch: Incorrect size: required:{} actual:{} (line {})",
                    required_len, s.length(), __LINE__));

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
            throw UnexpectedException(
                fmt::format("Unexpected: sodium_hex2bin failed", __LINE__));
        if (required_len && bin_len != required_len)
            throw LengthMismatchException(
                fmt::format("LengthMismatch: Incorrect size: required:{} actual:{} (line {})",
                    required_len, bin_len, __LINE__));
        return vec;
    }

    static BinaryVector fromBinary(const BinaryView &bv, size_t required_len=0)
    {
        return fromBinary(bv.data(), bv.size(), required_len);
    }

    static BinaryVector fromBinary(const uint8_t *p, size_t len, size_t required_len=0)
    {
        BinaryVector vec;

        if (required_len && len != required_len)
            throw LengthMismatchException(
                fmt::format("LengthMismatch: Incorrect size: required:{} actual:{} (line {})",
                    required_len, len, __LINE__));

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

    V2_LOCAL = 20,
    V2_PUBLIC = 21,
    V2_SECRET = 22,

    V3_LOCAL = 30,
    V3_PUBLIC = 31,
    V3_SECRET = 32,

    V4_LOCAL = 40,
    V4_PUBLIC = 41,
    V4_SECRET = 42,
};

constexpr const char* KeyTypeToString(KeyType k) throw()
{
    switch (k)
    {
        case KeyType::UNKNOWN: return "unknown";
        case KeyType::V2_LOCAL: return "V2_LOCAL";
        case KeyType::V2_PUBLIC: return "V2_PUBLIC";
        case KeyType::V2_SECRET: return "V2_SECRET";
        case KeyType::V3_LOCAL: return "V3_LOCAL";
        case KeyType::V3_PUBLIC: return "V3_PUBLIC";
        case KeyType::V3_SECRET: return "V3_SECRET";
        case KeyType::V4_LOCAL: return "V4_LOCAL";
        case KeyType::V4_PUBLIC: return "V4_PUBLIC";
        case KeyType::V4_SECRET: return "V4_SECRET";
        default: return "unknown";
    }
}


constexpr const char* KeyTypeToHeader(KeyType k) throw()
{
    switch (k)
    {
        case KeyType::UNKNOWN: return "unknown";
        case KeyType::V2_LOCAL: return "v2.local";
        case KeyType::V2_PUBLIC: return "v2.public";
        case KeyType::V2_SECRET: return "v2.public";
        case KeyType::V3_LOCAL: return "v3.local";
        case KeyType::V3_PUBLIC: return "v3.public";
        case KeyType::V3_SECRET: return "v3.public";
        case KeyType::V4_LOCAL: return "v4.local";
        case KeyType::V4_PUBLIC: return "v4.public";
        case KeyType::V4_SECRET: return "v4.public";
        default: return "unknown";
    }
}

constexpr bool isKeyTypeLocal(KeyType k)
{
    return ((int)k % 10 == 0);
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
        _payload = Binary::fromBinary(payload, payload_length);
        _footer = Binary::fromBinary(footer, footer_len);
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

    std::string toHex() const
    {
        return _data.toHex();
    }

    void checkKey() const
    {
        if (!_is_loaded)
            throw InvalidKeyException(
                fmt::format("InvalidKey: the key data has not been loaded (line {})", __LINE__));
        if (!paseto_init())
            throw UnexpectedException(
                fmt::format("Unexpected: paseto_init() failed (line {})", __LINE__));
    }

    virtual std::string encrypt(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a LOCAL key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual Token decrypt(
                const std::string_view &token,
                const BinaryView &implicit_assertion = Binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a LOCAL key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::string sign(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a SECRET key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual Token verify(
                const std::string_view &token,
                const BinaryView &implicit_assertion = Binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a PUBLIC key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

#ifdef DEBUG
    void setNonce(const std::string &nonce_hex, const BinaryView &payload)
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
            _nonce = Binary::fromHex(nonce_hex, 32);
        }
        else
            throw UnsupportedException(
                fmt::format("Unsupported: nonce not supported (line {})", __LINE__));
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
    std::string encrypt(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          _data.data(),
                          footer.data(), footer.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        std::string s{result};
        return s;
    }

    Token decrypt(
                const std::string_view &token,
                const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fdecrypt(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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

    Token verify(
                const std::string_view &token,
                const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fverify(token.data(), &message_len,
                          _data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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

    std::string sign(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fsign(payload.data(), payload.size(),
                       _data.data(),
                       footer.data(), footer.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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
    std::string encrypt(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const override
    {
        checkKey();

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          _data.data(),
                          footer.data(), footer.size(),
                          implicit_assertion.data(), implicit_assertion.size(),
                          _nonce.data(), _nonce.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        std::string s{result};
        return s;
    }

    Token decrypt(
                const std::string_view &token,
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
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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

    Token verify(
                const std::string_view &token,
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
                          &footer, &footer_len,
                          implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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

    std::string sign(
                const BinaryView &payload,
                const BinaryView &footer = Binary::none,
                const BinaryView &implicit_assertion = Binary::none) const override
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
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
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

            case KeyType::V4_LOCAL:
                return std::make_unique<PasetoV4LocalKey>();
            case KeyType::V4_PUBLIC:
                return std::make_unique<PasetoV4PublicKey>();
            case KeyType::V4_SECRET:
                return std::make_unique<PasetoV4SecretKey>();

            default:
                throw InvalidKeyException(
                    fmt::format("InvalidKey: unsupported keytype: {}({}) (line {})",
                        KeyTypeToString(type), (int) type, __LINE__));
        }
    }

    static std::unique_ptr<Key> createFromBinary(KeyType type, const BinaryView &bv)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromBinary(bv, key->_required_length);
        key->_is_loaded = true;
        return key;

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

template<KeyType kt, size_t public_size, size_t secret_size, auto fgenerate>
std::pair<std::unique_ptr<Key>, std::unique_ptr<Key>> generateKeyPair(const BinaryView &seed)
{
    BinaryVector binPublic;
    BinaryVector binSecret;
    binPublic.resize(public_size);
    binSecret.resize(secret_size);

    if (!fgenerate(seed.data(), seed.size(),
            binPublic.data(), binPublic.size(),
            binSecret.data(), binSecret.size()))
        throw UnexpectedException("y");

    return std::make_pair(
                Keys::createFromBinary(KeyType::V4_PUBLIC, binPublic),
                Keys::createFromBinary(KeyType::V4_SECRET, binSecret));
}



class KeyGen
{
public:
    static std::pair<std::unique_ptr<Key>, std::unique_ptr<Key>> generatePair(KeyType kt,
        const BinaryView &seed)
    {
        switch (kt)
        {
            case KeyType::V2_PUBLIC:
                return generateKeyPair<
                    KeyType::V2_PUBLIC,
                    paseto_v2_PUBLIC_PUBLICKEYBYTES,
                    paseto_v2_PUBLIC_SECRETKEYBYTES,
                    paseto_v2_public_generate_keys>(seed);
            case KeyType::V4_PUBLIC:
                return generateKeyPair<
                    KeyType::V4_PUBLIC,
                    paseto_v4_PUBLIC_PUBLICKEYBYTES,
                    paseto_v4_PUBLIC_SECRETKEYBYTES,
                    paseto_v4_public_generate_keys>(seed);
            default:
                throw InvalidKeyException(
                    fmt::format("InvalidKey: unsupported keytype: {}({}) (line {})",
                        KeyTypeToString(kt), (int) kt, __LINE__));
        }
    }
};


}; /* namespace:paseto */

#endif /* INCLUDE_PASETO_HPP */

