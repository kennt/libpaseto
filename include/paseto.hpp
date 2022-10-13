// Implementation based on pyseto

#ifndef INCLUDE_PASETO_HPP
#define INCLUDE_PASETO_HPP

extern "C" {
#include <sodium.h>
#include "paseto.h"
#include "paserk.h"
};
#include "helpers.hpp"

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

#include "cryptopp/filters.h"
#include "pem.h"

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

    bool operator==(const BinaryVector &other)
    {
        return std::operator==(*this, other);
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

    std::string toBase64() const
    {
        std::string result;
        size_t estimated_len = sodium_base64_ENCODED_LEN(this->size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        result.resize(estimated_len+1);
        sodium_bin2base64(
            result.data(), result.length(),
            this->data(), this->size(),
            sodium_base64_VARIANT_URLSAFE_NO_PADDING);
        result.resize(strlen(result.data()));
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

    ~BinaryVector()
    {
        if (!this->empty())
            sodium_memzero(this->data(), this->size());
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
            vec.resize((s.length()+2)*sizeof(uint8_t)/2);

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

constexpr const char * KeyTypePurpose(KeyType k)
{
    switch ((int) k % 10)
    {
        case 0: return "local";
        case 1: return "public";
        case 2: return "secret";
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


struct PasswordParams
{
    union {
        v2PasswordParams v2;
        v3PasswordParams v3;
        v4PasswordParams v4;
    } params;
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

    uint8_t * data()
    {
        return _data.data();
    }

    size_t size()
    {
        return _data.size();
    }

    size_t required_length() const
    {
        return _required_length;
    }

    bool is_loaded() const
    {
        return _is_loaded;
    }

    void clear()
    {
        _data.clear();
        _data.resize(_required_length);
        _is_loaded = false;
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

    virtual std::string toPaserkId()
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string toPaserk()
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string toPaserkWrap(const BinaryView &wrapping_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string toPaserkSeal(const BinaryView &public_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string toPaserkSeal(Key * public_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string toPaserkPassword(const std::string &pw, struct PasswordParams *opts)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual void fromPaserk(const std::string& paserk_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual void fromPaserkWrap(const std::string &paserk, const BinaryView &sk)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual void fromPaserkSeal(const std::string &paserk, const BinaryView &sk)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual void fromPaserkSeal(const std::string &paserk, Key * secret_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual void fromPaserkPassword(const std::string &paserk, const std::string &password)
    {
        throw UnexpectedException("Not yet implemented");
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

    bool operator==(const Key & other)
    {
        return this->_is_loaded == other._is_loaded &&
               this->_key_type == other._key_type &&
               this->_data == other._data;
    }

    std::string dump()
    {
        return fmt::format(" key_type:{} is_loaded:{} data:{}",
            KeyTypeToHeader(_key_type), _is_loaded, _data.toHex());
    }

protected:
    bool _is_loaded;
    BinaryVector _data;
    size_t _required_length;
    KeyType _key_type;

    BinaryVector _nonce;

private:
    friend class Keys;
};


// Helper functions


template<typename T>
using FN_TOPASERK =  char * (*)(uint8_t *, const char *, const uint8_t *, size_t, T *);

using FN_FROMPASERK =  bool (*)(uint8_t *, const char *, size_t, const uint8_t *, size_t);

template<typename T>
using FN_CONVERT_PARAMS =  T * (*)(struct PasswordParams *);

v2PasswordParams * convert_v2(struct PasswordParams *p)
{
    return p == NULL ? NULL : &(p->params.v2);
}

v3PasswordParams * convert_v3(struct PasswordParams *p)
{
    return p == NULL ? NULL : &(p->params.v3);
}

v4PasswordParams * convert_v4(struct PasswordParams *p)
{
    return p == NULL ? NULL : &(p->params.v4);
}


template<typename T, FN_TOPASERK<T> topaserk>
std::string buildPaserk(paseto::Key *key, const std::string &paserk_id,
    const uint8_t *secret, size_t secret_len, T * opts)
{
    if (!paseto_init())
        throw UnexpectedException(
                fmt::format("Unexpected: paseto_init() failed (line {})", __LINE__));

    char * paserk_key = nullptr;
    auto guard = paseto::on_scope_exit( [&]()
        { paseto_free(paserk_key);  });

    paserk_key = topaserk(key->data(), paserk_id.c_str(), secret, secret_len, opts);
    if (paserk_key == NULL)
        throw UnexpectedException(
            fmt::format("Unexpected: {}({}) (line {})",
                std::strerror(errno), errno, __LINE__));

    std::string result(paserk_key);
    return result;
}

template<typename T, FN_FROMPASERK frompaserk>
void loadPaserk(paseto::Key *key,
    const std::string &paserk_id,
    const std::string &paserk,
    const uint8_t *secret, size_t secret_len)
{
    if (!paseto_init())
        throw UnexpectedException(
                fmt::format("Unexpected: paseto_init() failed (line {})", __LINE__));

    key->clear();

    // These checks are redudant (they are also performed in the C api)
    // But we also do them here because we can provide more info in the
    // exception.
    if (key->size() != key->required_length())
        throw UnexpectedException(
            fmt::format("unexpected: key size:%zu != required size:%zu (line %d)\n",
                key->size(), key->required_length(), __LINE__));

    // algorithm lucidity check
    size_t data_start_pos = paserk.find_last_of('.');
    if (data_start_pos == std::string::npos)
        throw UnexpectedException(
            fmt::format("Unexpected: this is not a Paserk formatted key (line {})", __LINE__));
    data_start_pos += 1;

    if (paserk_id.compare(paserk.substr(0,data_start_pos)) != 0)
        throw UnexpectedException(
            fmt::format("Unexpected: incorrect key type: {}  expected:{}. (line {})",
                paserk.substr(0,data_start_pos), paserk_id, __LINE__));

    if (!frompaserk(key->data(), paserk.data(), paserk.length(), secret, secret_len))
        throw UnexpectedException(
            fmt::format("Unexpected: {}({}) (line {})",
                std::strerror(errno), errno, __LINE__));
}


template<typename T, enum KeyType key_type, size_t key_length,
         auto fencrypt, auto fdecrypt, auto topaserk, auto frompaserk, auto fnconvert>
class LocalKey : public Key
{
public:
    LocalKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.lid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    std::string toPaserkSeal(const BinaryView &pk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.seal.", KeyTypeVersion(_key_type)), pk.data(), pk.size(), NULL);
    }

    std::string toPaserkSeal(Key * public_key) override
    {
        if (public_key == NULL)
            throw UnexpectedException("unexpected: a public_key must be provided");

        // Only public keys of the same version are allowed
        // Although technically v2 and v4 are interchangeable
        if (KeyTypeVersion(_key_type) != KeyTypeVersion(public_key->keyType()))
            throw UnexpectedException(
                fmt::format("unexpected: key version mismatch: actual:{} expected:{}",
                    KeyTypeVersion(public_key->keyType()), KeyTypeVersion(_key_type)));
        if (strcmp(KeyTypePurpose(public_key->keyType()), "public") != 0)
            throw UnexpectedException(
                fmt::format("unexpected: must be a public key: actual:{}",
                    KeyTypePurpose(public_key->keyType())));

        public_key->checkKey();
        return toPaserkSeal(BinaryView(public_key->data(), public_key->size()));
    }

    void fromPaserkSeal(const std::string &paserk, const BinaryView &sk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.seal.", KeyTypeVersion(_key_type)),
            paserk, sk.data(), sk.size());

        _is_loaded = true;
    }

    void fromPaserkSeal(const std::string &paserk, Key * secret_key) override
    {
        if (secret_key == NULL)
            throw UnexpectedException("unexpected: a secret_key must be provided");

        // Only secret keys of the same version are allowed
        // Although technically v2 and v4 are interchangeable
        if (KeyTypeVersion(_key_type) != KeyTypeVersion(secret_key->keyType()))
            throw UnexpectedException(
                fmt::format("unexpected: key version mismatch: actual:{} expected:{}",
                    KeyTypeVersion(secret_key->keyType()), KeyTypeVersion(_key_type)));
        if (strcmp(KeyTypePurpose(secret_key->keyType()), "secret") != 0)
            throw UnexpectedException(
                fmt::format("unexpected: must be a secret key: actual:{}",
                    KeyTypePurpose(secret_key->keyType())));

        secret_key->checkKey();

        fromPaserkSeal(paserk, BinaryView(secret_key->data(), secret_key->size()));
    }

    std::string toPaserkWrap(const BinaryView &wk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(_key_type)), wk.data(), wk.size(), NULL);
    }

    void fromPaserkWrap(const std::string &paserk, const BinaryView &wk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(_key_type)),
            paserk, wk.data(), wk.size());

        _is_loaded = true;
    }

    std::string toPaserkPassword(const std::string &pw, struct PasswordParams *opts) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local-pw.", KeyTypeVersion(_key_type)),
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(), fnconvert(opts));
    }


    void fromPaserkPassword(const std::string &paserk, const std::string &password) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local-pw.", KeyTypeVersion(_key_type)),
            paserk, reinterpret_cast<const uint8_t *>(password.data()), password.length());

        _is_loaded = true;
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

protected:

};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fverify, auto topaserk, auto frompaserk, auto fnconvert>
class PublicKey : public Key
{
public:
    PublicKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.pid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
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

protected:
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fsign, auto topaserk, auto frompaserk, auto fnconvert>
class SecretKey : public Key
{
public:
    SecretKey()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.sid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    std::string toPaserkWrap(const BinaryView &wk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(_key_type)), wk.data(), wk.size(), NULL);
    }

    void fromPaserkWrap(const std::string &paserk, const BinaryView &wk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(_key_type)),
            paserk, wk.data(), wk.size());

        _is_loaded = true;
    }

    std::string toPaserkPassword(const std::string &pw, struct PasswordParams *opts) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret-pw.", KeyTypeVersion(_key_type)),
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(), fnconvert(opts));
    }


    void fromPaserkPassword(const std::string &paserk, const std::string &password) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret-pw.", KeyTypeVersion(_key_type)),
            paserk, reinterpret_cast<const uint8_t *>(password.data()), password.length());

        _is_loaded = true;
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

protected:
    // Helper functions
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fencrypt, auto fdecrypt, auto topaserk, auto frompaserk, auto fnconvert>
class LocalKey2 : public Key
{
public:
    LocalKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.lid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    std::string toPaserkSeal(const BinaryView &pk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.seal.", KeyTypeVersion(_key_type)), pk.data(), pk.size(), NULL);
    }

    std::string toPaserkSeal(Key * public_key) override
    {
        if (public_key == NULL)
            throw UnexpectedException("unexpected: a public_key must be provided");

        // Only public keys of the same version are allowed
        // Although technically v2 and v4 are interchangeable
        if (KeyTypeVersion(_key_type) != KeyTypeVersion(public_key->keyType()))
            throw UnexpectedException(
                fmt::format("unexpected: key version mismatch: actual:{} expected:{}",
                    KeyTypeVersion(public_key->keyType()), KeyTypeVersion(_key_type)));
        if (strcmp(KeyTypePurpose(public_key->keyType()), "public") != 0)
            throw UnexpectedException(
                fmt::format("unexpected: must be a public key: actual:{}",
                    KeyTypePurpose(public_key->keyType())));

        public_key->checkKey();
        return toPaserkSeal(BinaryView(public_key->data(), public_key->size()));
    }

    void fromPaserkSeal(const std::string &paserk, const BinaryView &sk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.seal.", KeyTypeVersion(_key_type)),
            paserk, sk.data(), sk.size());

        _is_loaded = true;
    }

    void fromPaserkSeal(const std::string &paserk, Key * secret_key) override
    {
        if (secret_key == NULL)
            throw UnexpectedException("unexpected: a secret_key must be provided");

        // Only secret keys of the same version are allowed
        // Although technically v2 and v4 are interchangeable
        if (KeyTypeVersion(_key_type) != KeyTypeVersion(secret_key->keyType()))
            throw UnexpectedException(
                fmt::format("unexpected: key version mismatch: actual:{} expected:{}",
                    KeyTypeVersion(secret_key->keyType()), KeyTypeVersion(_key_type)));
        if (strcmp(KeyTypePurpose(secret_key->keyType()), "secret") != 0)
            throw UnexpectedException(
                fmt::format("unexpected: must be a secret key: actual:{}",
                    KeyTypePurpose(secret_key->keyType())));

        secret_key->checkKey();

        fromPaserkSeal(paserk, BinaryView(secret_key->data(), secret_key->size()));
    }

    std::string toPaserkWrap(const BinaryView &wk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(_key_type)), wk.data(), wk.size(), NULL);
    }

    void fromPaserkWrap(const std::string &paserk, const BinaryView &wk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(_key_type)),
            paserk, wk.data(), wk.size());

        _is_loaded = true;
    }

    std::string toPaserkPassword(const std::string &pw, struct PasswordParams *opts) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.local-pw.", KeyTypeVersion(_key_type)),
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(), fnconvert(opts));
    }


    void fromPaserkPassword(const std::string &paserk, const std::string &password) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.local-pw.", KeyTypeVersion(_key_type)),
            paserk, reinterpret_cast<const uint8_t *>(password.data()), password.length());

        _is_loaded = true;
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


template<typename T, enum KeyType key_type, size_t key_length,
         auto fverify, auto topaserk, auto frompaserk, auto fnconvert>
class PublicKey2 : public Key
{
public:
    PublicKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.pid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
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


template<typename T, enum KeyType key_type, size_t key_length,
         auto fsign, auto topaserk, auto frompaserk, auto fnconvert>
class SecretKey2 : public Key
{
public:
    SecretKey2()
    {
        _required_length = key_length;
        _key_type = key_type;
        _is_loaded = false;
    }

    std::string toPaserk() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(_key_type)),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string toPaserkId() override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.sid.", KeyTypeVersion(_key_type)), NULL, 0, NULL);
    }

    std::string toPaserkWrap(const BinaryView &wk) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(_key_type)), wk.data(), wk.size(), NULL);
    }

    void fromPaserkWrap(const std::string &paserk, const BinaryView &wk) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(_key_type)),
            paserk, wk.data(), wk.size());

        _is_loaded = true;
    }

    std::string toPaserkPassword(const std::string &pw, struct PasswordParams *opts) override
    {
        return buildPaserk<T, topaserk>(this,
            fmt::format("k{}.secret-pw.", KeyTypeVersion(_key_type)),
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(), fnconvert(opts));
    }


    void fromPaserkPassword(const std::string &paserk, const std::string &password) override
    {
        loadPaserk<T, frompaserk>(this,
            fmt::format("k{}.secret-pw.", KeyTypeVersion(_key_type)),
            paserk, reinterpret_cast<const uint8_t *>(password.data()), password.length());

        _is_loaded = true;
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


typedef LocalKey<v2PasswordParams,
            KeyType::V2_LOCAL,
            paseto_v2_LOCAL_KEYBYTES,
            paseto_v2_local_encrypt,
            paseto_v2_local_decrypt,
            paseto_v2_local_key_to_paserk,
            paseto_v2_local_key_from_paserk,
            convert_v2> PasetoV2LocalKey;
typedef PublicKey<v2PasswordParams,
            KeyType::V2_PUBLIC,
            paseto_v2_PUBLIC_PUBLICKEYBYTES,
            paseto_v2_public_verify,
            paseto_v2_public_key_to_paserk,
            paseto_v2_public_key_from_paserk,
            convert_v2> PasetoV2PublicKey;
typedef SecretKey<v2PasswordParams,
            KeyType::V2_SECRET,
            paseto_v2_PUBLIC_SECRETKEYBYTES,
            paseto_v2_public_sign,
            paseto_v2_secret_key_to_paserk,
            paseto_v2_secret_key_from_paserk,
            convert_v2> PasetoV2SecretKey;

typedef LocalKey2<v3PasswordParams,
            KeyType::V3_LOCAL,
            paseto_v3_LOCAL_KEYBYTES,
            paseto_v3_local_encrypt,
            paseto_v3_local_decrypt,
            paseto_v3_local_key_to_paserk,
            paseto_v3_local_key_from_paserk,
            convert_v3> PasetoV3LocalKey;
typedef PublicKey2<v3PasswordParams,
            KeyType::V3_PUBLIC,
            paseto_v3_PUBLIC_PUBLICKEYBYTES,
            paseto_v3_public_verify,
            paseto_v3_public_key_to_paserk,
            paseto_v3_public_key_from_paserk,
            convert_v3> PasetoV3PublicKey;
typedef SecretKey2<v3PasswordParams,
            KeyType::V3_SECRET,
            paseto_v3_PUBLIC_SECRETKEYBYTES,
            paseto_v3_public_sign,
            paseto_v3_secret_key_to_paserk,
            paseto_v3_secret_key_from_paserk,
            convert_v3> PasetoV3SecretKey;

typedef LocalKey2<v4PasswordParams,
            KeyType::V4_LOCAL,
            paseto_v4_LOCAL_KEYBYTES,
            paseto_v4_local_encrypt,
            paseto_v4_local_decrypt,
            paseto_v4_local_key_to_paserk,
            paseto_v4_local_key_from_paserk,
            convert_v4> PasetoV4LocalKey;
typedef PublicKey2<v4PasswordParams,
            KeyType::V4_PUBLIC,
            paseto_v4_PUBLIC_PUBLICKEYBYTES,
            paseto_v4_public_verify,
            paseto_v4_public_key_to_paserk,
            paseto_v4_public_key_from_paserk,
            convert_v4> PasetoV4PublicKey;
typedef SecretKey2<v4PasswordParams,
            KeyType::V4_SECRET,
            paseto_v4_PUBLIC_SECRETKEYBYTES,
            paseto_v4_public_sign,
            paseto_v4_secret_key_to_paserk,
            paseto_v4_secret_key_from_paserk,
            convert_v4> PasetoV4SecretKey;

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

    static std::unique_ptr<Key> loadFromBinary(KeyType type, const BinaryView &bv)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromBinary(bv, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> loadFromHex(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromHex(s, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> loadFromBase64(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = Binary::fromBase64(s, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> loadFromPem(KeyType type, const std::string &s)
    {
        if (type == KeyType::V3_PUBLIC)
        {
            CryptoPP::StringSource source(s, true);
            CryptoPP::DL_PublicKey_EC<CryptoPP::ECP> public_key;
            CryptoPP::PEM_Load(source, public_key);
            const CryptoPP::ECP::Point& q = public_key.GetPublicElement();
            return loadFromHex(type,
                        p384_publickey_to_hex(q.x, q.y.GetBit(0)));
        }
        else if (type == KeyType::V3_SECRET)
        {
            CryptoPP::StringSource source(s, true);
            CryptoPP::DL_PrivateKey_EC<CryptoPP::ECP> secret_key;
            CryptoPP::PEM_Load(source, secret_key);
            return loadFromHex(type,
                        p384_privatekey_to_hex(secret_key.GetPrivateExponent()));
        }
        else
        {
            throw UnsupportedException("unsupported");
        }
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
                Keys::loadFromBinary(KeyType::V4_PUBLIC, binPublic),
                Keys::loadFromBinary(KeyType::V4_SECRET, binSecret));
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
            case KeyType::V3_PUBLIC:
                return generateKeyPair<
                    KeyType::V3_PUBLIC,
                    paseto_v3_PUBLIC_PUBLICKEYBYTES,
                    paseto_v3_PUBLIC_SECRETKEYBYTES,
                    paseto_v3_public_generate_keys>(seed);
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

