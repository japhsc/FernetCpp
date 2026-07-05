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

FernetCpp is a single-header library. Copy `fernet.h`, `base64.h`, `endian.h` (and optionally `print.h`) into your project and include:

```cpp
#include "fernet.h"
```

### Generate a key

```cpp
#include "fernet.h"

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
#include <string>
#include <iostream>

int main() {
    // Create a Fernet instance with a generated key and 5-minute TTL
    FERNET fernet("", 300);

    std::string message = "Hello, Fernet!";

    // --- Encrypt ---
    BYTE* token = nullptr;
    size_t tokenLen = 0;

    fernet.encrypt64((BYTE*) message.data(), message.size(), &token, &tokenLen);

    std::string tokenStr((char*) token, tokenLen);
    std::cout << "Token: " << tokenStr << std::endl;

    // --- Decrypt ---
    BYTE* plain = nullptr;
    size_t plainLen = 0;

    if (fernet.decrypt64((BYTE*) tokenStr.data(), tokenStr.size(), &plain, &plainLen)) {
        std::string decrypted((char*) plain, plainLen);
        std::cout << "Decrypted: " << decrypted << std::endl;
        free(plain);
    } else {
        std::cerr << "Decryption failed (wrong key, expired, or tampered token)."
                  << std::endl;
    }

    free(token);
    return 0;
}
```

### Error handling with `encrypt` / `decrypt`

The binary `encrypt` and `decrypt` methods return fine-grained error codes:

```cpp
BYTE* token = nullptr;
size_t tokenLen = 0;

int result = fernet.encrypt((BYTE*) data.data(), data.size(), &token, &tokenLen);
switch (result) {
    case FERNET_OK:            /* success */          break;
    case FERNET_ERROR_POINTER: /* null input */       break;
    case FERNET_ERROR_MALLOC:  /* allocation failed */ break;
}
free(token);
```

For convenience, `encrypt64` and `decrypt64` wrap these as `bool` return values and include base64 encoding/decoding - use these for most cases.

## API

### Constructor

```cpp
FERNET(std::string key = "", uint64_t ttl_sec = 60)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `key` | `""` (auto-generate) | Base64-encoded Fernet key (256 bits signing + 256 bits encryption) |
| `ttl_sec` | `60` | Maximum token age in seconds before decryption fails |

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_key()` | `std::string` | The Fernet key (generated or supplied) |
| `encrypt(plain, plainLen, &token, &tokenLen)` | `int` (error code) | Encrypt to binary Fernet token. Caller must `free(token)`. |
| `decrypt(token, tokenLen, &plain, &plainLen)` | `int` (error code) | Decrypt binary Fernet token. Caller must `free(plain)`. |
| `encrypt64(plain, plainLen, &token, &tokenLen)` | `bool` | Encrypt to base64-encoded token. Caller must `free(token)`. |
| `decrypt64(token, tokenLen, &plain, &plainLen)` | `bool` | Decrypt base64-encoded token. Caller must `free(plain)`. |

`plain`, `token` are `BYTE*` (i.e., `unsigned char*`). `&plain` and `&token` are **output parameters** - pass the address of your pointer; the function allocates memory you must `free()`.

### Error codes

| Constant | Value | Meaning |
|----------|-------|---------|
| `FERNET_OK` | `0` | Success |
| `FERNET_ERROR_POINTER` | `-1` | Null pointer passed |
| `FERNET_ERROR_MALLOC` | `-2` | Memory allocation failed |
| `FERNET_ERROR_VERSION` | `-3` | Wrong Fernet version byte |
| `FERNET_ERROR_TIMESTAMP` | `-4` | Token expired (age > TTL) |
| `FERNET_ERROR_WRONG_KEY` | `-5` | HMAC verification failed |

### Free function

```cpp
std::string get_key_from_password(std::string& password)
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
