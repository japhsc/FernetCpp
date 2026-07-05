#ifndef FERNET_H
#define FERNET_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>

#include "base64.h"
#include "endian.h"

#include <chrono>
#include <ctime>  // std::time

#include <cstdlib>  // malloc, free
#include <cstring>  // memcpy, memset
#include <cassert>  // assert
#include <optional>
#include <string_view>
#include <vector>

namespace fernet {

constexpr auto FERNET_VERSION = 0x80;

constexpr auto FERNET_OK = 0;
constexpr auto FERNET_ERROR_POINTER = -1;
constexpr auto FERNET_ERROR_MALLOC = -2;
constexpr auto FERNET_ERROR_VERSION = -3;
constexpr auto FERNET_ERROR_TIMESTAMP = -4;
constexpr auto FERNET_ERROR_WRONG_KEY = -5;

[[nodiscard]] static std::string get_key_from_password(std::string_view password) {
    CryptoPP::SHA256 hash;
    BYTE digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (BYTE*) password.data(), password.size());
    /*
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();
    */

    BYTE* _token = 0;
    size_t _tokenLen;
    base64_encode(digest, CryptoPP::SHA256::DIGESTSIZE, &_token, &_tokenLen);
    std::string key((char*) _token, _tokenLen);
    free(_token);
    return key;
}

class FERNET {
    /*
     * TOKEN:
     * <--------HEADER---------> <--cipher--> <--->
     * Version | Timestamp | IV | Ciphertext | HMAC
     */
private:
    uint64_t ttl_sec;

    const int block_len = CryptoPP::AES::BLOCKSIZE;
    const size_t header_len = 1 + sizeof(uint64_t) + block_len;
    const size_t hmac_len = CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE;
    const int key_len = CryptoPP::AES::DEFAULT_KEYLENGTH;
    const size_t fernet_key_len = 2 * key_len;

    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::SecByteBlock aes_key;
    CryptoPP::SecByteBlock sgn_key;

    std::string str_key;

    CryptoPP::SecByteBlock generate_key(int keylength) {
        // Generate a random key
        CryptoPP::SecByteBlock key(0x00, keylength);
        rnd.GenerateBlock(key, key.size());
        return key;
    }

    int pad_len(size_t len, int blocksize) noexcept { return blocksize - len % blocksize; }

    bool pad(BYTE* cipher, size_t* cipherLen) {
        int paddLen = pad_len(*cipherLen, block_len);
        size_t newLen = *cipherLen + paddLen;
        memset(cipher + *cipherLen, paddLen, paddLen);
        *cipherLen = newLen;
        return true;
    }

    bool unpad(BYTE* cipher, size_t* cipherLen) {
        if (*cipherLen == 0 || *cipherLen > block_len + 256)
            return false;
        unsigned char paddLen = *(cipher + *cipherLen - 1);
        if (paddLen == 0 || paddLen > block_len || paddLen > *cipherLen)
            return false;
        *cipherLen -= paddLen;
        return true;
    }

    bool byte_HMAC(BYTE* cipher, size_t* cipherLen, BYTE* d) {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(sgn_key, sgn_key.size());
        hmac.Update(cipher, *cipherLen);
        hmac.Final(d);
        return true;
    }

    bool byte_encrypt(
        const CryptoPP::SecByteBlock& iv, BYTE* plain, BYTE* cipher, size_t* cipherLen) {
        memcpy(cipher, plain, *cipherLen);
        if (pad(cipher, cipherLen)) {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
            e.SetKeyWithIV(aes_key, aes_key.size(), iv);
            e.ProcessData(cipher, cipher, *cipherLen);
            return true;
        }
        return false;
    }

    bool byte_decrypt(
        const CryptoPP::SecByteBlock& iv, BYTE* cipher, BYTE* plain, size_t* plainLen) {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(aes_key, aes_key.size(), iv);
        d.ProcessData(plain, cipher, *plainLen);
        if (unpad(plain, plainLen))
            return true;
        return false;
    }

    uint64_t timestamp() noexcept {
        auto unix_timestamp = std::chrono::seconds(std::time(NULL));
        return (uint64_t) unix_timestamp.count();
    }

    uint64_t timestamp_big() noexcept {
        // Timestamp: 64-bit unsigned big-endian integer
        return system_to_big_endian(timestamp());
    }

    bool valid_age(const uint64_t ts_big) noexcept {
        int64_t t0 = big_to_system_endian(ts_big);
        int64_t t1 = timestamp();
        uint64_t delta = llabs(t1 - t0);
        return (delta < ttl_sec);
    }

public:
    FERNET(std::string_view _key = "", uint64_t _ttl_sec = 60): ttl_sec(_ttl_sec) {
        BYTE* byte_key;
        size_t byte_key_len;
        base64_decode((const BYTE*) _key.data(), _key.size(), &byte_key, &byte_key_len);
        if (byte_key_len == fernet_key_len) {
            const BYTE* byte_sgn = byte_key;
            const BYTE* byte_aes = byte_sgn + key_len;
            sgn_key = CryptoPP::SecByteBlock(byte_sgn, key_len);
            aes_key = CryptoPP::SecByteBlock(byte_aes, key_len);
            str_key = _key;
        } else {
            sgn_key = generate_key(key_len);
            aes_key = generate_key(key_len);
            BYTE* b_key = (BYTE*) malloc(fernet_key_len);
            assert(b_key);
            memcpy(b_key, sgn_key.data(), sgn_key.size());
            memcpy(b_key + sgn_key.size(), aes_key.data(), aes_key.size());
            BYTE* b_key_enc;
            size_t b_key_enc_len;
            base64_encode(b_key, fernet_key_len, &b_key_enc, &b_key_enc_len);
            str_key = std::string((char*) b_key_enc, b_key_enc_len);
            free(b_key);
            free(b_key_enc);
        }
        free(byte_key);
    }

    ~FERNET() {}

    [[nodiscard]] std::string get_key() { return str_key; }

    /// Encrypt plaintext into a Fernet token.
    /// @param plain       Input plaintext bytes
    /// @param plain_len   Length of the plaintext
    /// @return The Fernet token bytes, or std::nullopt on error
    [[nodiscard]] std::optional<std::vector<BYTE>> encrypt(
        const BYTE* plain, size_t plain_len) {
        if (!plain)
            return std::nullopt;

        size_t cipher_len = plain_len + pad_len(plain_len, block_len);
        size_t token_len = header_len + cipher_len + hmac_len;
        std::vector<BYTE> token(token_len);

        BYTE* header = token.data();
        BYTE* cipher = header + header_len;
        BYTE* tsdata = header + sizeof(BYTE);
        BYTE* ivdata = tsdata + sizeof(uint64_t);

        *header = (BYTE) FERNET_VERSION;

        uint64_t ts = timestamp_big();
        memcpy(tsdata, &ts, sizeof(uint64_t));

        CryptoPP::SecByteBlock iv(block_len);
        rnd.GenerateBlock(iv, iv.size());
        memcpy(ivdata, iv.data(), iv.size());

        cipher_len = plain_len;
        if (!byte_encrypt(iv, const_cast<BYTE*>(plain), cipher, &cipher_len))
            return std::nullopt;

        size_t pre_token_len = header_len + cipher_len;
        BYTE* hmac = token.data() + pre_token_len;
        byte_HMAC(token.data(), &pre_token_len, hmac);

        token.resize(pre_token_len + hmac_len);
        return token;
    }

    /// Decrypt a Fernet token back into plaintext.
    /// @param token       Input Fernet token bytes
    /// @param token_len   Length of the token
    /// @return The decrypted plaintext, or std::nullopt on error
    [[nodiscard]] std::optional<std::vector<BYTE>> decrypt(
        const BYTE* token, size_t token_len) {
        if (!token)
            return std::nullopt;

        const BYTE* version = token;
        const BYTE* byte_ts = token + sizeof(BYTE);
        const BYTE* byte_iv = token + sizeof(BYTE) + sizeof(uint64_t);
        const BYTE* cipher = token + header_len;

        if (*version != FERNET_VERSION)
            return std::nullopt;

        uint64_t ts;
        memcpy(&ts, byte_ts, sizeof(uint64_t));
        if (!valid_age(ts))
            return std::nullopt;

        if (!verify(token, token_len))
            return std::nullopt;

        size_t plain_len = token_len - header_len - hmac_len;
        std::vector<BYTE> plain(plain_len);

        CryptoPP::SecByteBlock iv(byte_iv, block_len);
        if (!byte_decrypt(iv, const_cast<BYTE*>(cipher), plain.data(), &plain_len))
            return std::nullopt;

        plain.resize(plain_len);
        return plain;
    }

    [[nodiscard]] bool verify(const BYTE* _token, size_t _tokenLen) {
        if (!_token)
            return false;
        size_t preTokenLen = _tokenLen - hmac_len;
        const BYTE* hmac_token = _token + preTokenLen;
        BYTE hmac_calc[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
        byte_HMAC(const_cast<BYTE*>(_token), &preTokenLen, hmac_calc);
        volatile int result = 0;
        for (size_t i = 0; i < hmac_len; ++i)
            result |= hmac_token[i] ^ hmac_calc[i];
        return result == 0;
    }

    /// Encrypt plaintext and return a base64-encoded Fernet token string.
    /// @param plain       Input plaintext bytes
    /// @param plain_len   Length of the plaintext
    /// @return Base64-encoded token string, or std::nullopt on error
    [[nodiscard]] std::optional<std::string> encrypt64(
        const BYTE* plain, size_t plain_len) {
        auto cipher = encrypt(plain, plain_len);
        if (!cipher)
            return std::nullopt;
        BYTE* b64 = nullptr;
        size_t b64_len = 0;
        base64_encode(cipher->data(), cipher->size(), &b64, &b64_len);
        std::string result((char*) b64, b64_len);
        free(b64);
        return result;
    }

    /// Decrypt a base64-encoded Fernet token back into plaintext.
    /// @param token       Input base64-encoded Fernet token bytes
    /// @param token_len   Length of the base64-encoded token
    /// @return The decrypted plaintext, or std::nullopt on error
    [[nodiscard]] std::optional<std::vector<BYTE>> decrypt64(
        const BYTE* token, size_t token_len) {
        BYTE* raw = nullptr;
        size_t raw_len = 0;
        base64_decode(token, token_len, &raw, &raw_len);
        auto result = decrypt(raw, raw_len);
        free(raw);
        return result;
    }
};

} // namespace fernet

#endif
