// FernetCpp compatibility test
// Build: g++ -std=c++17 -I. test_fernet.cpp -o test_fernet -lcryptopp

#include "fernet.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace fernet;

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
        auto token = fernet.encrypt64(
            (const BYTE*) compatMsg.data(), compatMsg.size());
        if (token)
            std::cout << *token;
        return token ? 0 : 1;
    }

    std::cout << "FernetCpp Tests" << std::endl << "===============" << std::endl;

    // -- C++ round-trip -------------------------------------------------

    std::cout << "C++ round-trip:" << std::endl;

    TEST("encrypt64/decrypt64");
    {
        FERNET fernet("", 300);
        std::string msg = "Hello, Fernet!";

        auto token = fernet.encrypt64(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        auto plain = fernet.decrypt64(
            (const BYTE*) token->data(), token->size());

        if (plain && plain->size() == msg.size()
            && memcmp(plain->data(), msg.data(), plain->size()) == 0) {
            OK;
        } else {
            FAIL("round-trip mismatch");
        }
    }

    TEST("encrypt/decrypt (binary)");
    {
        FERNET fernet("", 300);
        std::string msg = "binary test";

        auto token = fernet.encrypt(
            (const BYTE*) msg.data(), msg.size());
        if (!token) {
            FAIL("encrypt failed");
        } else {
            auto plain = fernet.decrypt(token->data(), token->size());
            if (plain && plain->size() == msg.size()
                && memcmp(plain->data(), msg.data(), plain->size()) == 0) {
                OK;
            } else {
                FAIL("decrypt failed");
            }
        }
    }

    TEST("encrypt64/decrypt64 empty message");
    {
        FERNET fernet("", 300);
        std::string msg;

        auto token = fernet.encrypt64(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        auto plain = fernet.decrypt64(
            (const BYTE*) token->data(), token->size());

        if (plain && plain->size() == 0) {
            OK;
        } else {
            FAIL("empty round-trip mismatch");
        }
    }

    TEST("decrypt with wrong key fails");
    {
        FERNET fernet1("", 300);
        FERNET fernet2("", 300);
        std::string msg = "secret";

        auto token = fernet1.encrypt64(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        auto plain = fernet2.decrypt64(
            (const BYTE*) token->data(), token->size());
        if (!plain) {
            OK;
        } else {
            FAIL("should have failed with wrong key");
        }
    }

    TEST("decrypt expired token fails");
    {
        FERNET fernet("", 0);  // 0-second TTL
        std::string msg = "expired";

        auto token = fernet.encrypt64(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        auto plain = fernet.decrypt64(
            (const BYTE*) token->data(), token->size());
        if (!plain) {
            OK;
        } else {
            FAIL("should have failed (expired)");
        }
    }

    TEST("decrypt tampered token fails");
    {
        FERNET fernet("", 300);
        std::string msg = "tamper me";

        auto token = fernet.encrypt(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        // Flip a bit in the HMAC portion (last byte)
        token->back() ^= 0x01;

        auto plain = fernet.decrypt(token->data(), token->size());
        if (!plain) {
            OK;
        } else {
            FAIL("should have failed (tampered token)");
        }
    }

    TEST("decrypt wrong version byte fails");
    {
        FERNET fernet("", 300);
        std::string msg = "version test";

        auto token = fernet.encrypt64(
            (const BYTE*) msg.data(), msg.size());
        assert(token);

        // Decode, flip version byte, re-encode
        BYTE* raw = nullptr;
        size_t rawLen = 0;
        base64_decode((const BYTE*) token->data(), token->size(), &raw, &rawLen);
        raw[0] ^= 0xFF;  // corrupt version byte
        BYTE* badToken = nullptr;
        size_t badTokenLen = 0;
        base64_encode(raw, rawLen, &badToken, &badTokenLen);

        std::string badStr((char*) badToken, badTokenLen);
        auto plain = fernet.decrypt64(
            (const BYTE*) badStr.data(), badStr.size());
        if (!plain) {
            OK;
        } else {
            FAIL("should have failed (wrong version)");
        }
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

    TEST("encrypt with null plain returns nullopt");
    {
        FERNET fernet("", 300);
        auto token = fernet.encrypt(nullptr, 10);
        if (!token) {
            OK;
        } else {
            FAIL("expected nullopt");
        }
    }

    TEST("decrypt with null token returns nullopt");
    {
        FERNET fernet("", 300);
        auto plain = fernet.decrypt(nullptr, 100);
        if (!plain) {
            OK;
        } else {
            FAIL("expected nullopt");
        }
    }

    // -- Python Fernet compatibility -------------------------------------

    std::cout << "Python Fernet compatibility:" << std::endl;

    // Generate a fresh token internally to avoid TTL expiry.
    // The Python cross-check is handled by test_compat.py.
    auto freshToken = [](bool pad) -> std::string {
        FERNET f(compatKey, 600);
        auto tok = f.encrypt64(
            (const BYTE*) compatMsg.data(), compatMsg.size());
        assert(tok);
        if (!pad && !tok->empty() && tok->back() == '=')
            tok->pop_back();
        return *tok;
    };

    TEST("decrypt self-encrypted token (padded)");
    {
        std::string tok = freshToken(true);
        FERNET fernet(compatKey, 600);
        auto plain = fernet.decrypt64(
            (const BYTE*) tok.data(), tok.size());
        if (plain && plain->size() == compatMsg.size()
            && memcmp(plain->data(), compatMsg.data(), plain->size()) == 0) {
            OK;
        } else {
            FAIL("failed to decrypt token (padded)");
        }
    }

    TEST("decrypt self-encrypted token (unpadded)");
    {
        std::string tok = freshToken(false);
        FERNET fernet(compatKey, 600);
        auto plain = fernet.decrypt64(
            (const BYTE*) tok.data(), tok.size());
        if (plain && plain->size() == compatMsg.size()
            && memcmp(plain->data(), compatMsg.data(), plain->size()) == 0) {
            OK;
        } else {
            FAIL("failed to decrypt token (unpadded)");
        }
    }

    TEST("C++ encrypt/decrypt with Python-generated key");
    {
        FERNET fernet(compatKey, 3600);
        auto token = fernet.encrypt64(
            (const BYTE*) compatMsg.data(), compatMsg.size());
        assert(token);

        auto plain = fernet.decrypt64(
            (const BYTE*) token->data(), token->size());

        if (plain && plain->size() == compatMsg.size()
            && memcmp(plain->data(), compatMsg.data(), plain->size()) == 0) {
            OK;
        } else {
            FAIL("round-trip with Python key failed");
        }
    }

    // -- Summary ---------------------------------------------------------

    std::cout << "---------------" << std::endl;
    std::cout << passed << "/" << tests << " tests passed." << std::endl;
    return (passed == tests) ? 0 : 1;
}
