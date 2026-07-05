# FernetCpp

An implementation of [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) in C++ - symmetric authenticated encryption with automatic timestamp-based expiry.

## Dependencies

- [Crypto++](https://www.cryptopp.com/) - install via apt or build from source:
  ```sh
  # Debian / Ubuntu
  sudo apt install libcrypto++-dev

  # Or build from source
  git clone https://github.com/weidai11/cryptopp.git
  cd cryptopp && make -j$(nproc) && sudo make install
  ```
- C++17 or later

## Usage

FernetCpp is a single-header library. Copy `fernet.h`, `base64.h`, and `endian.h` into your project and include:

```cpp
#include "fernet.h"
```

### Generate a key

```cpp
#include "fernet.h"

using namespace fernet;

// Generate a random key
FERNET fernet;
std::string key = fernet.get_key();
std::cout << "Key: " << key << std::endl;
```

Or derive a key from a password:

```cpp
std::string password = "my-secret-password";
std::string key = get_key_from_password(password);
FERNET fernet(key);
```

### Encrypt and decrypt

```cpp
#include "fernet.h"
#include <iostream>
#include <string>

using namespace fernet;

int main() {
    // Create a Fernet instance with a generated key and 5-minute TTL
    FERNET fernet("", 300);

    std::string message = "Hello, Fernet!";

    // --- Encrypt ---
    auto token = fernet.encrypt64(
        (const BYTE*) message.data(), message.size());
    if (!token) {
        std::cerr << "Encryption failed." << std::endl;
        return 1;
    }
    std::cout << "Token: " << *token << std::endl;

    // --- Decrypt ---
    auto plain = fernet.decrypt64(
        (const BYTE*) token->data(), token->size());

    if (plain) {
        std::string decrypted((char*) plain->data(), plain->size());
        std::cout << "Decrypted: " << decrypted << std::endl;
    } else {
        std::cerr << "Decryption failed (wrong key, expired, or tampered token)."
                  << std::endl;
    }

    return 0;
}
```

### Binary API

When you don't need base64 encoding, use the binary `encrypt` and `decrypt` directly:

```cpp
auto token = fernet.encrypt(
    (const BYTE*) data.data(), data.size());

if (token) {
    auto plain = fernet.decrypt(token->data(), token->size());
    if (plain) {
        // use plain->data(), plain->size()
    }
}
```

## API

### Constructor

```cpp
FERNET(std::string_view key = "", uint64_t ttl_sec = 60)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `key` | `""` (auto-generate) | Base64-encoded Fernet key (256 bits signing + 256 bits encryption) |
| `ttl_sec` | `60` | Maximum token age in seconds before decryption fails |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_key()` | `std::string` | The Fernet key (generated or supplied) |
| `encrypt(plain, plain_len)` | `std::optional<std::vector<BYTE>>` | Encrypt to binary Fernet token |
| `decrypt(token, token_len)` | `std::optional<std::vector<BYTE>>` | Decrypt binary Fernet token |
| `encrypt64(plain, plain_len)` | `std::optional<std::string>` | Encrypt to base64-encoded token string |
| `decrypt64(token, token_len)` | `std::optional<std::vector<BYTE>>` | Decrypt base64-encoded token |

All input pointers are `const BYTE*`. Return values are `std::nullopt` on failure (null input, wrong key, expired, tampered, or malformed token). No manual memory management needed.

### Free function

```cpp
[[nodiscard]] std::string get_key_from_password(std::string_view password)
```

Derives a base64-encoded Fernet key from a password using SHA-256.

## Building

```sh
# Compile your program with Crypto++
g++ -std=c++17 -I. main.cpp -o main -lcryptopp
```

## Testing

```sh
make test    # build and run the compatibility test suite
```

The test suite verifies C++ round-trips, error handling, and cross-compatibility with Python Fernet (`cryptography` library).

## Formatting

```sh
make format        # reformat all headers
make format-check  # check (CI-ready)
```
