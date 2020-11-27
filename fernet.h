#ifndef FERNET_H
#define	FERNET_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/hmac.h>

#include "base64.h"
#include "endian.h"

#include <chrono>
#include <ctime>		// std::time

#include <stdlib.h>     // malloc, realloc
#include <assert.h>     // assert

constexpr auto FERNET_VERSION = 0x80;

constexpr auto FERNET_OK = 1;
constexpr auto FERNET_ERROR_POINTER = 0;
constexpr auto FERNET_ERROR_MALLOC = -1;
constexpr auto FERNET_ERROR_VERSION = -2;
constexpr auto FERNET_ERROR_TIMESTAMP = -3;
constexpr auto FERNET_ERROR_WRONG_KEY = -4;

std::string get_key_from_password(std::string &password) {
    CryptoPP::SHA256 hash;
    BYTE digest[CryptoPP::SHA256::DIGESTSIZE];
    hash.CalculateDigest(digest, (BYTE*) password.c_str(), password.length() );
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
	 * Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC
	*/
	private:
		
		uint64_t ttl_sec;
		
		const int block_len = CryptoPP::AES::BLOCKSIZE;
		const size_t header_len = 1+sizeof(uint64_t)+block_len;
		const size_t hmac_len = CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE;
		const int key_len = CryptoPP::AES::DEFAULT_KEYLENGTH;
		const size_t fernet_key_len = 2*key_len;
		
		CryptoPP::AutoSeededRandomPool rnd;
		CryptoPP::SecByteBlock aes_key;
		CryptoPP::SecByteBlock sgn_key;

		std::string str_key;
		
		CryptoPP::SecByteBlock generate_key(int keylength){
			// Generate a random key
			CryptoPP::SecByteBlock key(0x00, keylength);
			rnd.GenerateBlock(key, key.size());
			return key;
		}
		
		int pad_len(size_t len, int blocksize) {
			return blocksize - len%blocksize;
		}
		
		bool pad(BYTE* cipher, size_t *cipherLen){
			int paddLen = pad_len(*cipherLen, block_len);
			size_t newLen = *cipherLen + paddLen;
			memset(cipher+*cipherLen, paddLen, paddLen);
			*cipherLen = newLen;
			return true;
		}

		bool unpad(BYTE* cipher, size_t *cipherLen){
			char paddLen = *(cipher + *cipherLen - 1);
			*cipherLen -= (size_t) paddLen;
			return true;
		}

		bool byte_HMAC(BYTE* cipher, size_t *cipherLen, byte* d){
			CryptoPP::HMAC< CryptoPP::SHA256 > hmac(sgn_key, sgn_key.size());
			hmac.Update(cipher, *cipherLen);
			hmac.Final(d);
			return true;
		}

		bool byte_encrypt(const CryptoPP::SecByteBlock &iv, BYTE* plain, BYTE* cipher, size_t *cipherLen) {
			memcpy(cipher, plain, *cipherLen);
			if (pad(cipher, cipherLen)) {
				CryptoPP::CBC_Mode< CryptoPP::AES >::Encryption e;
				e.SetKeyWithIV( aes_key, aes_key.size(), iv);
				e.ProcessData(cipher, cipher, *cipherLen);
				return true;
			}
			return false;
		}

		bool byte_decrypt(const CryptoPP::SecByteBlock &iv, BYTE* cipher, BYTE* plain, size_t *plainLen) {
			CryptoPP::CBC_Mode< CryptoPP::AES >::Decryption d;
			d.SetKeyWithIV( aes_key, aes_key.size(), iv);
			d.ProcessData(plain, cipher, *plainLen);
			if (unpad(plain, plainLen))
				return true;
			return false;
		}

		uint64_t timestamp() {
            auto unix_timestamp = std::chrono::seconds(std::time(NULL));
			return (uint64_t) unix_timestamp.count();
		}

		uint64_t timestamp_big() {
			// Timestamp: 64-bit unsigned big-endian integer
			return system_to_big_endian(timestamp());
		}

		bool valid_age(const uint64_t ts_big) {
			int64_t t0 = big_to_system_endian(ts_big);
			int64_t t1 = timestamp();
			uint64_t delta = abs(t1-t0);
			return (delta < ttl_sec);
		}
	
	public:
	    FERNET(std::string _key="", uint64_t _ttl_sec=60):ttl_sec(_ttl_sec){
			BYTE* byte_key;
			size_t byte_key_len;
			base64_decode((BYTE*)_key.data(), _key.size(), &byte_key, &byte_key_len);
			if (byte_key_len==fernet_key_len) {
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
				memcpy(b_key+sgn_key.size(), aes_key.data(), aes_key.size());
				BYTE* b_key_enc;
				size_t b_key_enc_len;
				base64_encode(b_key, fernet_key_len, &b_key_enc, &b_key_enc_len);
				str_key = std::string((char*) b_key_enc, b_key_enc_len);
				free(b_key); free(b_key_enc);
			}
			free(byte_key);
		}
		
		~FERNET(){}
		
		std::string get_key(){
			return str_key;
		}
	
		int encrypt(	BYTE* _plain, const size_t _plain_len, 
						BYTE** _token, size_t *_token_len )
		{
			if (!_plain) return FERNET_ERROR_POINTER;

			// Buffer
			size_t cipher_len = _plain_len + pad_len(_plain_len, block_len);
			size_t token_len = header_len + cipher_len + hmac_len;
			*_token = (BYTE*) malloc(token_len);
			if (!*_token) return FERNET_ERROR_MALLOC;
			
			// token pointer
			BYTE* header = *_token;
			BYTE* cipher = header+header_len;
			BYTE* tsdata = header+sizeof(BYTE);
			BYTE* ivdata = tsdata+sizeof(uint64_t);
			
			// Version
			*header = (BYTE) FERNET_VERSION;
			
			// Timestamp
			uint64_t ts = timestamp_big();
			memcpy(tsdata, &ts, sizeof(uint64_t));
			
			// Generate a random IV
			CryptoPP::SecByteBlock iv(block_len);
			rnd.GenerateBlock(iv, iv.size());
			memcpy(ivdata, iv.data(), iv.size());
			
			// Encrypt
			cipher_len = _plain_len;
			byte_encrypt(iv, _plain, cipher, &cipher_len);
			
			size_t pre_token_len = header_len + cipher_len;
			BYTE* hmac = *_token+pre_token_len;
			byte_HMAC(*_token, &pre_token_len, hmac);
			
			*_token_len = pre_token_len+hmac_len;
			
			return FERNET_OK;
		}

		int decrypt(	BYTE* _token, const size_t _token_len, 
						BYTE** _plain, size_t *_plain_len)
		{
			if (!_token) return FERNET_ERROR_POINTER;
			
			// Buffer
			*_plain = (BYTE*) malloc(_token_len);
			if (!*_plain) return FERNET_ERROR_MALLOC;
			
			BYTE* version = _token;
			BYTE* byte_ts = _token+sizeof(BYTE);
			BYTE* byte_iv = _token+sizeof(BYTE)+sizeof(uint64_t);
			BYTE* cipher = _token + header_len;
			
			if (*version != FERNET_VERSION){
				free(*_plain);
				return FERNET_ERROR_VERSION;
			}
			
			uint64_t ts;
			memcpy(&ts, byte_ts, sizeof(uint64_t));
			if (!valid_age(ts)) {
				free(*_plain);
				return FERNET_ERROR_TIMESTAMP;
			}

			if (!verify(_token, _token_len)) {
				free(*_plain);
				return FERNET_ERROR_WRONG_KEY;
			}
			*_plain_len = _token_len - header_len - hmac_len;

			CryptoPP::SecByteBlock iv(byte_iv, block_len);
			byte_decrypt(iv, cipher, *_plain, _plain_len);
			return FERNET_OK;
		}
		
		bool verify(BYTE* _token, const size_t _tokenLen) {
			if (!_token) return false;
			size_t preTokenLen = _tokenLen - hmac_len;
			BYTE* hmac_token = _token + preTokenLen;
			BYTE* hmac_calc = (BYTE*) malloc(hmac_len);
			if (!hmac_calc) return false;
			byte_HMAC(_token, &preTokenLen, hmac_calc);
			volatile int result = 0;
			for (size_t i=0; i < hmac_len; ++i)
				result |= hmac_token[i]^hmac_calc[i];
			free(hmac_calc);
			return result == 0;
		}
		
		bool encrypt64(BYTE* _plain, const size_t _plainLen, BYTE** _token, size_t* _tokenLen) {
			BYTE* _cipher = 0;
			size_t _cipherLen;
			if (encrypt(_plain, _plainLen, &_cipher, &_cipherLen) != FERNET_OK)
				return false;
			base64_encode(_cipher, _cipherLen, _token, _tokenLen);
			free(_cipher);
			return true;
		}

		bool decrypt64(BYTE* _token, const size_t _tokenLen, BYTE** _plain, size_t* _plainLen) {
			BYTE* _cipher = 0;
			size_t _cipherLen;
			base64_decode(_token, _tokenLen, &_cipher, &_cipherLen);
			bool ret = decrypt(_cipher, _cipherLen, _plain, _plainLen);
			free(_cipher);
			return ret;
		}
		
};

#endif
