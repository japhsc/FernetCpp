// FernetCpp compatibility test
// Build: g++ -std=c++17 -I. test_fernet.cpp -o test_fernet -lcryptopp

#include "fernet.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

static int tests = 0, passed = 0;

// Key shared with Python compatibility tests
static const std::string compatKey = "azP7xePMjNqFOvXR4bCqQPYkGEpAWyBMrCZlX4vo1U4=";
static const std::string compatMsg = "Hello, Fernet!";

#define TEST(name)                              \
    do {                                        \
        tests++;                                \
        std::cout << "  " << (name) << " ... "; \
    } while (0)
#define OK                              \
    do {                                \
        passed++;                       \
        std::cout << "OK" << std::endl; \
    } while (0)
#define FAIL(msg)                                   \
    do {                                            \
        std::cout << "FAIL" << std::endl;           \
        std::cerr << "       " << msg << std::endl; \
    } while (0)

int main(int argc, char** argv) {
    // --token mode: output a token for Python cross-check
    if (argc == 2 && std::string(argv[1]) == "--token") {
        FERNET fernet(compatKey, 3600);
        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet.encrypt64((BYTE*) compatMsg.data(), compatMsg.size(), &token, &tokenLen);
        std::cout.write((char*) token, tokenLen);
        free(token);
        return 0;
    }

    std::cout << "FernetCpp Tests" << std::endl << "===============" << std::endl;

    // -- C++ round-trip -------------------------------------------------

    std::cout << "C++ round-trip:" << std::endl;

    TEST("encrypt64/decrypt64");
    {
        FERNET fernet("", 300);
        std::string msg = "Hello, Fernet!";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        assert(fernet.encrypt64((BYTE*) msg.data(), msg.size(), &token, &tokenLen));

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(token, tokenLen, &plain, &plainLen);

        if (ok && plainLen == msg.size() && memcmp(plain, msg.data(), plainLen) == 0) {
            OK;
        } else {
            FAIL("round-trip mismatch");
        }
        free(token);
        if (ok)
            free(plain);
    }

    TEST("encrypt/decrypt (binary, error codes)");
    {
        FERNET fernet("", 300);
        std::string msg = "binary test";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        int rc = fernet.encrypt((BYTE*) msg.data(), msg.size(), &token, &tokenLen);
        if (rc != FERNET_OK) {
            FAIL("encrypt returned " << rc);
            free(token);
        } else {
            BYTE* plain = nullptr;
            size_t plainLen = 0;
            rc = fernet.decrypt(token, tokenLen, &plain, &plainLen);
            if (rc == FERNET_OK && plainLen == msg.size()
                && memcmp(plain, msg.data(), plainLen) == 0) {
                OK;
            } else {
                FAIL("decrypt returned " << rc);
            }
            free(token);
            if (rc == FERNET_OK)
                free(plain);
        }
    }

    TEST("encrypt64/decrypt64 empty message");
    {
        FERNET fernet("", 300);
        std::string msg;

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        assert(fernet.encrypt64((BYTE*) msg.data(), msg.size(), &token, &tokenLen));

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(token, tokenLen, &plain, &plainLen);

        if (ok && plainLen == 0) {
            OK;
        } else {
            FAIL("empty round-trip mismatch");
        }
        free(token);
        if (ok)
            free(plain);
    }

    TEST("decrypt with wrong key fails");
    {
        FERNET fernet1("", 300);
        FERNET fernet2("", 300);
        std::string msg = "secret";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet1.encrypt64((BYTE*) msg.data(), msg.size(), &token, &tokenLen);

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet2.decrypt64(token, tokenLen, &plain, &plainLen);
        if (!ok) {
            OK;
        } else {
            FAIL("should have failed with wrong key");
            free(plain);
        }
        free(token);
    }

    TEST("decrypt expired token fails");
    {
        FERNET fernet("", 0);  // 0-second TTL
        std::string msg = "expired";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet.encrypt64((BYTE*) msg.data(), msg.size(), &token, &tokenLen);

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(token, tokenLen, &plain, &plainLen);
        if (!ok) {
            OK;
        } else {
            FAIL("should have failed (expired)");
            free(plain);
        }
        free(token);
    }

    TEST("decrypt tampered token fails");
    {
        FERNET fernet("", 300);
        std::string msg = "tamper me";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet.encrypt((BYTE*) msg.data(), msg.size(), &token, &tokenLen);

        // Flip a bit in the HMAC portion (last byte of raw binary token)
        token[tokenLen - 1] ^= 0x01;

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        int rc = fernet.decrypt(token, tokenLen, &plain, &plainLen);
        if (rc == FERNET_ERROR_WRONG_KEY) {
            OK;
        } else {
            FAIL("should have failed (tampered token), got " << rc);
        }
        free(token);
    }

    TEST("decrypt wrong version byte fails");
    {
        FERNET fernet("", 300);
        std::string msg = "version test";

        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet.encrypt64((BYTE*) msg.data(), msg.size(), &token, &tokenLen);

        // Decode, flip version byte, re-encode
        BYTE* raw = nullptr;
        size_t rawLen = 0;
        base64_decode(token, tokenLen, &raw, &rawLen);
        raw[0] ^= 0xFF;  // corrupt version byte
        BYTE* badToken = nullptr;
        size_t badTokenLen = 0;
        base64_encode(raw, rawLen, &badToken, &badTokenLen);

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(badToken, badTokenLen, &plain, &plainLen);
        if (!ok) {
            OK;
        } else {
            FAIL("should have failed (wrong version)");
            free(plain);
        }
        free(token);
        free(raw);
        free(badToken);
    }

    TEST("get_key returns valid base64");
    {
        FERNET fernet;
        std::string key = fernet.get_key();
        if (key.size() == 44) {
            OK;
        } else {
            FAIL("key length " << key.size() << " (expected 44)");
        }
    }

    TEST("get_key_from_password");
    {
        std::string pw = "my-password";
        std::string key = get_key_from_password(pw);
        if (key.size() == 44) {
            OK;
        } else {
            FAIL("key length " << key.size() << " (expected 44)");
        }
    }

    TEST("encrypt with null plain returns error");
    {
        FERNET fernet("", 300);
        BYTE* token = nullptr;
        size_t tokenLen = 0;
        int rc = fernet.encrypt(nullptr, 10, &token, &tokenLen);
        if (rc == FERNET_ERROR_POINTER) {
            OK;
        } else {
            FAIL("expected FERNET_ERROR_POINTER, got " << rc);
        }
    }

    TEST("decrypt with null token returns error");
    {
        FERNET fernet("", 300);
        BYTE* plain = nullptr;
        size_t plainLen = 0;
        int rc = fernet.decrypt(nullptr, 100, &plain, &plainLen);
        if (rc == FERNET_ERROR_POINTER) {
            OK;
        } else {
            FAIL("expected FERNET_ERROR_POINTER, got " << rc);
        }
    }

    // -- Python Fernet compatibility -------------------------------------

    std::cout << "Python Fernet compatibility:" << std::endl;

    // Generate a fresh token internally to avoid TTL expiry.
    // The Python cross-check is handled by test_compat.py.
    auto freshToken = [](bool pad) -> std::string {
        FERNET f(compatKey, 600);
        BYTE* t = nullptr;
        size_t tl = 0;
        f.encrypt64((BYTE*)compatMsg.data(), compatMsg.size(), &t, &tl);
        std::string s((char*)t, tl);
        free(t);
        if (!pad && !s.empty() && s.back() == '=')
            s.pop_back();
        return s;
    };

    TEST("decrypt self-encrypted token (padded)");
    {
        std::string tok = freshToken(true);
        FERNET fernet(compatKey, 600);
        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64((BYTE*) tok.data(), tok.size(), &plain, &plainLen);
        if (ok && plainLen == compatMsg.size() && memcmp(plain, compatMsg.data(), plainLen) == 0) {
            OK;
        } else {
            FAIL("failed to decrypt token (padded)");
        }
        if (ok)
            free(plain);
    }

    TEST("decrypt self-encrypted token (unpadded)");
    {
        std::string tok = freshToken(false);
        FERNET fernet(compatKey, 600);
        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(
            (BYTE*) tok.data(), tok.size(), &plain, &plainLen);
        if (ok && plainLen == compatMsg.size() && memcmp(plain, compatMsg.data(), plainLen) == 0) {
            OK;
        } else {
            FAIL("failed to decrypt token (unpadded)");
        }
        if (ok)
            free(plain);
    }

    TEST("C++ encrypt/decrypt with Python-generated key");
    {
        FERNET fernet(compatKey, 3600);
        BYTE* token = nullptr;
        size_t tokenLen = 0;
        fernet.encrypt64((BYTE*) compatMsg.data(), compatMsg.size(), &token, &tokenLen);

        BYTE* plain = nullptr;
        size_t plainLen = 0;
        bool ok = fernet.decrypt64(token, tokenLen, &plain, &plainLen);

        if (ok && plainLen == compatMsg.size() && memcmp(plain, compatMsg.data(), plainLen) == 0) {
            OK;
        } else {
            FAIL("round-trip with Python key failed");
        }
        free(token);
        if (ok)
            free(plain);
    }

    // -- Summary ---------------------------------------------------------

    std::cout << "---------------" << std::endl;
    std::cout << passed << "/" << tests << " tests passed." << std::endl;
    return (passed == tests) ? 0 : 1;
}
