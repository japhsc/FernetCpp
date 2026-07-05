#!/usr/bin/env python3
"""FernetCpp <-> Python Fernet two-way cross-compatibility test."""

import subprocess
import sys

from cryptography.fernet import Fernet

KEY = "azP7xePMjNqFOvXR4bCqQPYkGEpAWyBMrCZlX4vo1U4="
MSG = b"Hello, Fernet!"
CPP_BIN = "./test_fernet"

passed = 0
failed = 0


def test(name):
    """Run a named test. Usage: with test("name"): ..."""
    global passed, failed
    print(f"  {name} ... ", end="", flush=True)

    class _Test:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            global passed, failed
            if exc_type is None:
                print("OK")
                passed += 1
            else:
                print("FAIL")
                print(f"       {exc_val}")
                failed += 1
            return True  # suppress exception propagation

    return _Test()


def main():
    global passed, failed

    print("Python Fernet cross-compatibility")
    print("=================================")

    # --- Python -> Python (sanity) ---
    with test("Python encrypt/decrypt round-trip"):
        f = Fernet(KEY)
        token = f.encrypt(MSG)
        assert f.decrypt(token) == MSG

    # --- Python encrypts -> C++ decrypts (already tested in C++) ---
    with test("Python encrypt -> C++ decrypt (via test_fernet)"):
        result = subprocess.run([CPP_BIN], capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(
                f"test_fernet failed (exit {result.returncode})\n"
                f"stderr: {result.stderr}"
            )
        # Verify the Python-specific tests passed
        if "decrypt self-encrypted token (padded) ... OK" not in result.stdout:
            raise AssertionError("padded token test missing/failed")
        if "decrypt self-encrypted token (unpadded) ... OK" not in result.stdout:
            raise AssertionError("unpadded token test missing/failed")

    # --- C++ encrypts -> Python decrypts ---
    with test("C++ encrypt -> Python decrypt"):
        result = subprocess.run(
            [CPP_BIN, "--token"], capture_output=True, text=True
        )
        if result.returncode != 0:
            raise AssertionError(f"--token mode failed: {result.stderr}")

        cpp_token = result.stdout.strip()
        if not cpp_token:
            raise AssertionError("no token output from test_fernet --token")

        f = Fernet(KEY)
        decrypted = f.decrypt(cpp_token.encode())
        if decrypted != MSG:
            raise AssertionError(
                f"decrypted {decrypted!r} != expected {MSG!r}"
            )

    # --- Verify C++ token is a valid Fernet token ---
    with test("C++ token structure matches Fernet spec"):
        result = subprocess.run(
            [CPP_BIN, "--token"], capture_output=True, text=True
        )
        cpp_token = result.stdout.strip().encode()
        f = Fernet(KEY)
        decrypted = f.decrypt(cpp_token)
        if decrypted != MSG:
            raise AssertionError(
                f"decrypted {decrypted!r} != expected {MSG!r}"
            )
        # Verify standard Fernet token properties
        import base64
        raw = base64.urlsafe_b64decode(cpp_token)
        # Version byte must be 0x80
        if raw[0] != 0x80:
            raise AssertionError(f"version byte is {raw[0]:#x}, expected 0x80")
        # Token structure: 1 (version) + 8 (timestamp) + 16 (IV) + N (ciphertext) + 32 (HMAC)
        if len(raw) < 1 + 8 + 16 + 32:
            raise AssertionError(f"token too short: {len(raw)} bytes")

    # --- Summary ---
    total = passed + failed
    print("---------------")
    print(f"{passed}/{total} tests passed.")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
