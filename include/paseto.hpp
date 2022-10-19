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



class binary_view : public std::basic_string_view<uint8_t>
{
public:
    binary_view()
    {}

    binary_view(const uint8_t*p, size_t len)
        : std::basic_string_view<uint8_t>(p, len)
    {}

    binary_view(const std::string_view &sv)
        : std::basic_string_view<uint8_t>(
            reinterpret_cast<const uint8_t *>(sv.data()), sv.length())
    {}

    binary_view(const std::string &s)
        : std::basic_string_view<uint8_t>(
            reinterpret_cast<const uint8_t *>(s.data()), s.length())
    {}

    static binary_view fromString(const std::string_view s)
    {
        binary_view bin_view(s);
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

class binary : public std::vector<uint8_t>
{
public:
    operator binary_view() const
    {
        return binary_view(data(), size());
    }

    bool operator==(const binary &other)
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

    ~binary()
    {
        if (!this->empty())
            sodium_memzero(this->data(), this->size());
    }

    static binary fromHex(const std::string_view &s, size_t required_len=0)
    {
        binary vec;
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

    static binary fromString(const std::string_view &s, size_t required_len=0)
    {
        binary vec;

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

    static binary fromBase64(const std::string_view &s, size_t required_len=0)
    {
        binary vec;
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

    static binary fromBinary(const binary_view &bv, size_t required_len=0)
    {
        return fromBinary(bv.data(), bv.size(), required_len);
    }

    static binary fromBinary(const uint8_t *p, size_t len, size_t required_len=0)
    {
        binary vec;

        if (required_len && len != required_len)
            throw LengthMismatchException(
                fmt::format("LengthMismatch: Incorrect size: required:{} actual:{} (line {})",
                    required_len, len, __LINE__));

        vec.resize(len*sizeof(uint8_t));

        std::memcpy(vec.data(), p, len*sizeof(uint8_t));

        return vec;
    }

    inline static binary_view none;
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

inline KeyType makeKeyType(int version, const char *purpose)
{
    int kt = version*10;
    if (strcmp(purpose, "public") == 0) kt += 1;
    else if (strcmp(purpose, "secret") == 0) kt += 2;
    else if (strcmp(purpose, "local") == 0) kt += 0;
    else
        throw UnexpectedException("unexpected: ");
    return static_cast<KeyType>(kt);
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

constexpr bool isKeyTypeSecret(KeyType k)
{
    return ((int)k % 10 == 2);
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
        _payload = binary::fromBinary(payload, payload_length);
        _footer = binary::fromBinary(footer, footer_len);
    }

    const binary &payload()
    {
        return _payload;
    }
    const binary &footer()
    {
        return _footer;
    }
private:
    KeyType _key_type;
    binary _payload;
    binary _footer;
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
    static std::unique_ptr<Key> create(KeyType kt);

    std::string description()
    {
        return KeyTypeToString(_key_type);
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

    size_t size() const
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

    void set_is_loaded(bool value)
    {
        _is_loaded = value;
    }

    void clear()
    {
        sodium_memzero(&_data[0], _data.size());
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
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a LOCAL key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual Token decrypt(
                const std::string_view &token,
                const binary_view &implicit_assertion = binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a LOCAL key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::string sign(
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a SECRET key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual Token verify(
                const std::string_view &    ,
                const binary_view &implicit_assertion = binary::none) const
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: this is not a PUBLIC key:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::string paserkId()
    {
        throw UnexpectedException("Unexpected: Not yet implemented");
    }

    virtual std::string toPaserk()
    {
        throw UnexpectedException("Unexpected: Not yet implemented");
    }

    virtual void fromPaserk(const std::string& paserk_key)
    {
        throw UnexpectedException("Not yet implemented");
    }

    virtual std::string wrap(Key *key)
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: only LOCAL keys can be used to wrap:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::unique_ptr<Key> unwrap(const std::string &paserk)
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: only LOCAL keys can be used to wrap:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::string seal(Key *local_key)
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: only PUBLIC keys can be used to seal:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    virtual std::unique_ptr<Key> unseal(const std::string &paserk)
    {
        throw InvalidKeyException(
            fmt::format("InvalidKey: only SECRET keys can be used to unseal:{} (line {})",
                KeyTypeToString(_key_type), __LINE__));
    }

    void _checkExpectedKeyType(const char *operation_desc,
        int expected_version, const char *expected_purpose,
        KeyType kt)
    {
        // Only keys of the same version are allowed
        if (expected_version != KeyTypeVersion(kt))
            throw UnexpectedException(
                fmt::format("unexpected: {} : key version mismatch: actual:{} expected:{}",
                    operation_desc,
                    KeyTypeVersion(kt), expected_version));
        if (strcmp(KeyTypePurpose(kt), expected_purpose) != 0)
            throw UnexpectedException(
                fmt::format("unexpected: {} : must be a {} key: actual:{}",
                    operation_desc, expected_purpose,
                    KeyTypePurpose(kt)));
    }


#ifdef DEBUG
    void setNonce(const std::string &nonce_hex, const binary_view &payload)
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
            _nonce = binary::fromHex(nonce_hex, 32);
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

    std::string dump()
    {
        return fmt::format(" key_type:{} is_loaded:{} data:{}",
            KeyTypeToString(_key_type), _is_loaded, _data.toHex());
    }

protected:
    bool _is_loaded;
    binary _data;
    size_t _required_length;
    KeyType _key_type;

    binary _nonce;

private:
    friend class Keys;
    friend bool operator==(const Key&, const Key&);
};


inline bool operator==(const Key &lhs, const Key &rhs)
{
    return lhs.is_loaded() == rhs.is_loaded() &&
           lhs.keyType() == lhs.keyType() &&
           lhs.size() == rhs.size() &&
           lhs._data == rhs._data;
}

inline bool operator!=(const Key &lhs, const Key &rhs)
{
    return !(lhs == rhs);
}


inline std::ostream& operator<< ( std::ostream& os, const paseto::Key & value ) {
    os << "loaded:" << value.is_loaded() << " type:" << KeyTypeToString(value.keyType())
       << " len:" << value.size() << " data:" << value.toHex();
    return os;
};


// Helper functions

template<typename T>
using FN_TOPASERK =  char * (*)(uint8_t *, const char *, const uint8_t *, size_t, T *);

using FN_FROMPASERK =  bool (*)(uint8_t *, const char *, size_t, const uint8_t *, size_t);

template<typename T>
using FN_CONVERT_PARAMS =  T * (*)(struct PasswordParams *);

inline v2PasswordParams * convert_v2(struct PasswordParams *p)
{
    return p == NULL ? NULL : &(p->params.v2);
}

inline v3PasswordParams * convert_v3(struct PasswordParams *p)
{
    return p == NULL ? NULL : &(p->params.v3);
}

inline v4PasswordParams * convert_v4(struct PasswordParams *p)
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

    // These checks are redundant (they are also performed in the C api)
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
            fmt::format("Unexpected: incorrect key type: {}  expected:{} (line {})",
                paserk.substr(0,data_start_pos), paserk_id, __LINE__));

    if (!frompaserk(key->data(), paserk.data(), paserk.length(), secret, secret_len))
        throw UnexpectedException(
            fmt::format("Unexpected: {}({}) (line {})",
                std::strerror(errno), errno, __LINE__));
}


template<typename T, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class LocalKeyPaserkImpl : public Key
{
public:
    std::string toPaserk() override
    {
        return buildPaserk<T, tolocalpaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }
    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, fromlocalpaserk>(this,
            fmt::format("k{}.local.", KeyTypeVersion(this->keyType())),
            paserk, NULL, 0);

        this->_is_loaded = true;
    }

    std::string paserkId() override
    {
        return buildPaserk<T, tolocalpaserk>(this,
            fmt::format("k{}.lid.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }

    std::string wrap(Key *key) override
    {
        if (key == NULL)
            throw UnexpectedException("unexpected: a local or secret key must be provided");

        // Only keys of the same version are allowed
        KeyType kt = key->keyType();
        if (KeyTypeVersion(this->keyType()) != KeyTypeVersion(kt))
            throw UnexpectedException(
                fmt::format("unexpected: paserk-wrap : key version mismatch: actual:{} expected:{}",
                    KeyTypeVersion(kt), KeyTypeVersion(this->keyType())));

        if (!isKeyTypeLocal(kt) && !isKeyTypeSecret(kt))
            throw UnexpectedException(
                fmt::format("unexpected: paserk-wrap : must be a local or secret key: actual:{}",
                    KeyTypePurpose(kt)));

        key->checkKey();

        if (isKeyTypeLocal(kt))
        {
            return buildPaserk<T, tolocalpaserk>(key,
               fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(kt)),
                this->data(), this->size(), NULL);
        }
        else
        {
            return buildPaserk<T, tosecretpaserk>(key,
               fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(kt)),
                this->data(), this->size(), NULL);
        }
    }

    std::unique_ptr<Key> unwrap(const std::string &paserk) override
    {
        this->checkKey();

        // Determine the key type
        KeyType kt = this->keyType();
        std::string local_header = fmt::format("k{}.local-wrap.pie.", KeyTypeVersion(kt));
        std::string secret_header = fmt::format("k{}.secret-wrap.pie.", KeyTypeVersion(kt));
        std::unique_ptr<Key> key;
        if (paserk.compare(0, local_header.length(), local_header) == 0)
        {
            key = Key::create(makeKeyType(KeyTypeVersion(kt), "local"));
            loadPaserk<T, fromlocalpaserk>(key.get(), local_header,
                paserk, this->data(), this->size());
        }
        else if (paserk.compare(0, secret_header.length(), secret_header) == 0)
        {
            key = Key::create(makeKeyType(KeyTypeVersion(kt), "secret"));
            loadPaserk<T, fromsecretpaserk>(key.get(), secret_header,
                paserk, this->data(), this->size());
        }
        else
            throw UnexpectedException("unexpected: ");

        key->set_is_loaded(true);
        return key;

    }
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fencrypt, auto fdecrypt, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class LocalKey : public LocalKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    LocalKey()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    // A base64 encoded string is returned
    std::string encrypt(
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          this->_data.data(),
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
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fdecrypt(token.data(), &message_len,
                          this->_data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        return Token(this->keyType(), result, message_len, footer, footer_len);
    }

protected:

};


template<typename T, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class PublicKeyPaserkImpl : public Key
{
public:
    std::string toPaserk() override
    {
        return buildPaserk<T, topublicpaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, frompublicpaserk>(this,
            fmt::format("k{}.public.", KeyTypeVersion(this->keyType())),
            paserk, NULL, 0);

        _is_loaded = true;
    }

    std::string paserkId() override
    {
        return buildPaserk<T, topublicpaserk>(this,
            fmt::format("k{}.pid.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }


    std::string seal(Key *local_key) override
    {
        if (local_key == NULL)
            throw UnexpectedException("unexpected: a local_key must be provided");

        _checkExpectedKeyType("paserk-seal",
            KeyTypeVersion(this->keyType()), "local", local_key->keyType());

        local_key->checkKey();

        return buildPaserk<T, tolocalpaserk>(local_key,
            fmt::format("k{}.seal.", KeyTypeVersion(this->keyType())),
            this->data(), this->size(), NULL);
    }

};


template<typename T, enum KeyType key_type, size_t key_length,
        auto fverify, auto tolocalpaserk, auto fromlocalpaserk,
        auto topublicpaserk, auto frompublicpaserk,
        auto tosecretpaserk, auto fromsecretpaserk,
        auto fnconvert>
class PublicKey : public PublicKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    PublicKey()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    Token verify(
                const std::string_view &token,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fverify(token.data(), &message_len,
                          this->_data.data(),
                          &footer, &footer_len);
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        return Token(this->keyType(), result, message_len, footer, footer_len);
    }

protected:
};


template<typename T, auto tolocalpaserk, auto fromlocalpaserk,
        auto topublicpaserk, auto frompublicpaserk,
        auto tosecretpaserk, auto fromsecretpaserk,
        auto fnconvert>
class SecretKeyPaserkImpl : public Key
{
public:
    std::string toPaserk() override
    {
        return buildPaserk<T, tosecretpaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }

    void fromPaserk(const std::string &paserk) override
    {
        loadPaserk<T, fromsecretpaserk>(this,
            fmt::format("k{}.secret.", KeyTypeVersion(this->keyType())),
            paserk, NULL, 0);

        this->_is_loaded = true;
    }

    std::string paserkId() override
    {
        return buildPaserk<T, tosecretpaserk>(this,
            fmt::format("k{}.sid.", KeyTypeVersion(this->keyType())), NULL, 0, NULL);
    }

    std::unique_ptr<Key> unseal(const std::string &paserk) override
    {
        this->checkKey();

        auto key = Key::create(makeKeyType(KeyTypeVersion(this->keyType()), "local"));

        loadPaserk<T, fromlocalpaserk>(key.get(),
            fmt::format("k{}.seal.", KeyTypeVersion(this->keyType())),
            paserk, this->data(), this->size());

        key->set_is_loaded(true);
        return key;
    }
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fsign, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class SecretKey : public SecretKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    SecretKey()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    std::string sign(
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        if (implicit_assertion.length() > 0)
            throw UnsupportedException(
                fmt::format("Unsupported: This version does not support implicit_assertion (line {})", __LINE__));

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fsign(payload.data(), payload.size(),
                       this->_data.data(),
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
         auto fencrypt, auto fdecrypt,
         auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class LocalKey2 : public LocalKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    LocalKey2()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    // A base64 encoded string is returned
    std::string encrypt(
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fencrypt(payload.data(), payload.size(),
                          this->_data.data(),
                          footer.data(), footer.size(),
                          implicit_assertion.data(), implicit_assertion.size(),
                          this->_nonce.data(), this->_nonce.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        std::string s{result};
        return s;
    }

    Token decrypt(
                const std::string_view &token,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fdecrypt(token.data(), &message_len,
                          this->_data.data(),
                          &footer, &footer_len,
                          implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        return Token(this->keyType(), result, message_len, footer, footer_len);
    }
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fverify, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class PublicKey2 : public PublicKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    PublicKey2()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    Token verify(
                const std::string_view &token,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        size_t message_len = 0, footer_len = 0;
        uint8_t *footer = nullptr;
        uint8_t *result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(footer); paseto_free(result);  });

        result = fverify(token.data(), &message_len,
                          this->_data.data(),
                          &footer, &footer_len,
                          implicit_assertion.data(), implicit_assertion.size());
        if (result == NULL)
            throw UnexpectedException(
                fmt::format("Unexpected: {}({}) (line {})",
                    std::strerror(errno), errno, __LINE__));
        return Token(this->keyType(), result, message_len, footer, footer_len);
    }
};


template<typename T, enum KeyType key_type, size_t key_length,
         auto fsign, auto tolocalpaserk, auto fromlocalpaserk,
         auto topublicpaserk, auto frompublicpaserk,
         auto tosecretpaserk, auto fromsecretpaserk,
         auto fnconvert>
class SecretKey2 : public SecretKeyPaserkImpl<T, tolocalpaserk, fromlocalpaserk,
                                            topublicpaserk, frompublicpaserk,
                                            tosecretpaserk, fromsecretpaserk,
                                            fnconvert>
{
public:
    SecretKey2()
    {
        this->_required_length = key_length;
        this->_key_type = key_type;
        this->_is_loaded = false;
    }

    std::string sign(
                const binary_view &payload,
                const binary_view &footer = binary::none,
                const binary_view &implicit_assertion = binary::none) const override
    {
        this->checkKey();

        char * result = nullptr;
        auto guard = paseto::on_scope_exit( [&]()
            { paseto_free(result);  });

        result = fsign(payload.data(), payload.size(),
                       this->_data.data(),
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
            paseto_v2_public_key_to_paserk,
            paseto_v2_public_key_from_paserk,
            paseto_v2_secret_key_to_paserk,
            paseto_v2_secret_key_from_paserk,
            convert_v2> PasetoV2LocalKey;
typedef PublicKey<v2PasswordParams,
            KeyType::V2_PUBLIC,
            paseto_v2_PUBLIC_PUBLICKEYBYTES,
            paseto_v2_public_verify,
            paseto_v2_local_key_to_paserk,
            paseto_v2_local_key_from_paserk,
            paseto_v2_public_key_to_paserk,
            paseto_v2_public_key_from_paserk,
            paseto_v2_secret_key_to_paserk,
            paseto_v2_secret_key_from_paserk,
            convert_v2> PasetoV2PublicKey;
typedef SecretKey<v2PasswordParams,
            KeyType::V2_SECRET,
            paseto_v2_PUBLIC_SECRETKEYBYTES,
            paseto_v2_public_sign,
            paseto_v2_local_key_to_paserk,
            paseto_v2_local_key_from_paserk,
            paseto_v2_public_key_to_paserk,
            paseto_v2_public_key_from_paserk,
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
            paseto_v3_public_key_to_paserk,
            paseto_v3_public_key_from_paserk,
            paseto_v3_secret_key_to_paserk,
            paseto_v3_secret_key_from_paserk,
            convert_v3> PasetoV3LocalKey;
typedef PublicKey2<v3PasswordParams,
            KeyType::V3_PUBLIC,
            paseto_v3_PUBLIC_PUBLICKEYBYTES,
            paseto_v3_public_verify,
            paseto_v3_local_key_to_paserk,
            paseto_v3_local_key_from_paserk,
            paseto_v3_public_key_to_paserk,
            paseto_v3_public_key_from_paserk,
            paseto_v3_secret_key_to_paserk,
            paseto_v3_secret_key_from_paserk,
            convert_v3> PasetoV3PublicKey;
typedef SecretKey2<v3PasswordParams,
            KeyType::V3_SECRET,
            paseto_v3_PUBLIC_SECRETKEYBYTES,
            paseto_v3_public_sign,
            paseto_v3_local_key_to_paserk,
            paseto_v3_local_key_from_paserk,
            paseto_v3_public_key_to_paserk,
            paseto_v3_public_key_from_paserk,
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
            paseto_v4_public_key_to_paserk,
            paseto_v4_public_key_from_paserk,
            paseto_v4_secret_key_to_paserk,
            paseto_v4_secret_key_from_paserk,
            convert_v4> PasetoV4LocalKey;
typedef PublicKey2<v4PasswordParams,
            KeyType::V4_PUBLIC,
            paseto_v4_PUBLIC_PUBLICKEYBYTES,
            paseto_v4_public_verify,
            paseto_v4_local_key_to_paserk,
            paseto_v4_local_key_from_paserk,
            paseto_v4_public_key_to_paserk,
            paseto_v4_public_key_from_paserk,
            paseto_v4_secret_key_to_paserk,
            paseto_v4_secret_key_from_paserk,
            convert_v4> PasetoV4PublicKey;
typedef SecretKey2<v4PasswordParams,
            KeyType::V4_SECRET,
            paseto_v4_PUBLIC_SECRETKEYBYTES,
            paseto_v4_public_sign,
            paseto_v4_local_key_to_paserk,
            paseto_v4_local_key_from_paserk,
            paseto_v4_public_key_to_paserk,
            paseto_v4_public_key_from_paserk,
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

    static std::unique_ptr<Key> loadFromBinary(KeyType type, const binary_view &bv)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = binary::fromBinary(bv, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> loadFromHex(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = binary::fromHex(s, key->_required_length);
        key->_is_loaded = true;
        return key;
    }

    static std::unique_ptr<Key> loadFromBase64(KeyType type, const std::string_view &s)
    {
        std::unique_ptr<Key> key = Keys::create(type);
        key->_data = binary::fromBase64(s, key->_required_length);
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
            throw InvalidKeyException(
                    fmt::format("InvalidKey: unsupported keytype: {}({}) (line {})",
                        KeyTypeToString(type), (int) type, __LINE__));
        }
    }
};


inline std::unique_ptr<Key> Key::create(KeyType kt)
{
    return Keys::create(kt);
}

template<KeyType kt, size_t public_size, size_t secret_size, auto fgenerate>
std::pair<std::unique_ptr<Key>, std::unique_ptr<Key>> generateKeyPair(const binary_view &seed)
{
    binary binPublic;
    binary binSecret;
    binPublic.resize(public_size);
    binSecret.resize(secret_size);

    if (!fgenerate(seed.data(), seed.size(),
            binPublic.data(), binPublic.size(),
            binSecret.data(), binSecret.size()))
        throw UnexpectedException(
                fmt::format("Unexpected: key generation failed: {} {}({}) (line {})",
                    KeyTypeToString(kt),
                    std::strerror(errno), errno, __LINE__));

    return std::make_pair(
                Keys::loadFromBinary(kt, binPublic),
                Keys::loadFromBinary(makeKeyType(KeyTypeVersion(kt), "secret"), binSecret));
}

template<KeyType kt, size_t secret_size>
std::unique_ptr<Key> generateKey()
{
    binary secret;
    secret.resize(secret_size);
    randombytes_buf(secret.data(), secret.size());

    return Keys::loadFromBinary(kt, secret);
}


class KeyGen
{
public:
    static std::unique_ptr<Key> generate(KeyType kt)
    {
        switch (kt)
        {
            case KeyType::V2_LOCAL:
                return generateKey<KeyType::V2_LOCAL,
                                   paseto_v2_LOCAL_KEYBYTES>();
            case KeyType::V3_LOCAL:
                return generateKey<KeyType::V3_LOCAL,
                                   paseto_v3_LOCAL_KEYBYTES>();
            case KeyType::V4_LOCAL:
                return generateKey<KeyType::V4_LOCAL,
                                   paseto_v4_LOCAL_KEYBYTES>();
            default:
                throw InvalidKeyException(
                    fmt::format("InvalidKey: unsupported keytype: {}({}) (line {})",
                        KeyTypeToString(kt), (int) kt, __LINE__));
        }
    }

    static std::pair<std::unique_ptr<Key>, std::unique_ptr<Key>> generatePair(KeyType kt,
        const binary_view &seed = binary::none)
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

namespace paserk
{

inline std::string passwordWrap(paseto::Key *key, const std::string &pw, struct paseto::PasswordParams *opts)
{
    using namespace paseto;

    if (key == NULL)
        throw UnexpectedException("unexpected: a local or secret key must be provided");

    if (opts == NULL)
        throw UnexpectedException("unexpected: ");

    KeyType kt = key->keyType();
    if (!isKeyTypeLocal(kt) && !isKeyTypeSecret(kt))
        throw UnexpectedException(
                fmt::format("unexpected: paserk-password-wrap : must be a local or secret key: actual:{}",
                    KeyTypePurpose(kt)));

    key->checkKey();

    switch(kt)
    {
        case KeyType::V2_LOCAL:
            return buildPaserk<v2PasswordParams, paseto_v2_local_key_to_paserk>(
                key, "k2.local-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v2(opts));
        case KeyType::V2_SECRET:
            return buildPaserk<v2PasswordParams, paseto_v2_secret_key_to_paserk>(
                key, "k2.secret-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v2(opts));
        case KeyType::V3_LOCAL:
            return buildPaserk<v3PasswordParams, paseto_v3_local_key_to_paserk>(
                key, "k3.local-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v3(opts));
        case KeyType::V3_SECRET:
            return buildPaserk<v3PasswordParams, paseto_v3_secret_key_to_paserk>(
                key, "k3.secret-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v3(opts));
        case KeyType::V4_LOCAL:
            return buildPaserk<v4PasswordParams, paseto_v4_local_key_to_paserk>(
                key, "k4.local-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v4(opts));
        case KeyType::V4_SECRET:
            return buildPaserk<v4PasswordParams, paseto_v4_secret_key_to_paserk>(
                key, "k4.secret-pw.",
                reinterpret_cast<const uint8_t *>(pw.data()), pw.size(),
                paseto::convert_v4(opts));
        default:
            throw InvalidKeyException("invalid-key: ");
    }
}

inline std::unique_ptr<paseto::Key> passwordUnwrap(const std::string &paserk_key, const std::string &password)
{
    using namespace paseto;

    static std::string localv2  {"k2.local-pw."};
    static std::string secretv2 {"k2.secret-pw."};
    static std::string localv3  {"k3.local-pw."};
    static std::string secretv3 {"k3.secret-pw."};
    static std::string localv4  {"k4.local-pw."};
    static std::string secretv4 {"k4.secret-pw."};

    std::unique_ptr<Key> key;

    if (paserk_key.compare(0, localv2.length(), localv2) == 0)
    {
        key = Key::create(KeyType::V2_LOCAL);
        loadPaserk<v2PasswordParams, paseto_v2_local_key_from_paserk>(
            key.get(), localv2, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else if (paserk_key.compare(0, secretv2.length(), secretv2) == 0)
    {
        key = Key::create(KeyType::V2_SECRET);
        loadPaserk<v2PasswordParams, paseto_v2_secret_key_from_paserk>(
            key.get(), secretv2, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else if (paserk_key.compare(0, localv3.length(), localv3) == 0)
    {
        key = Key::create(KeyType::V3_LOCAL);
        loadPaserk<v3PasswordParams, paseto_v3_local_key_from_paserk>(
            key.get(), localv3, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else if (paserk_key.compare(0, secretv3.length(), secretv3) == 0)
    {
        key = Key::create(KeyType::V3_SECRET);
        loadPaserk<v3PasswordParams, paseto_v3_secret_key_from_paserk>(
            key.get(), secretv3, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else if (paserk_key.compare(0, localv4.length(), localv4) == 0)
    {
        key = Key::create(KeyType::V4_LOCAL);
        loadPaserk<v4PasswordParams, paseto_v4_local_key_from_paserk>(
            key.get(), localv4, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else if (paserk_key.compare(0, secretv4.length(), secretv4) == 0)
    {
        key = Key::create(KeyType::V4_SECRET);
        loadPaserk<v4PasswordParams, paseto_v4_secret_key_from_paserk>(
            key.get(), secretv4, paserk_key,
            reinterpret_cast<const uint8_t *>(password.data()), password.length());

        key->set_is_loaded(true);
    }
    else
        throw UnexpectedException("unexpected: ");

    return key;
}

};

#endif /* INCLUDE_PASETO_HPP */

