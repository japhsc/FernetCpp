.PHONY: format format-check test

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -I. -I/usr/local/include
LDFLAGS  ?= -L/usr/local/lib -lcryptopp

# Format all source files in-place
format:
	@clang-format -i *.h *.cpp

# Check if files are correctly formatted (for CI)
format-check:
	@clang-format --dry-run --Werror *.h *.cpp && echo "All files correctly formatted."

# Run the compatibility test suite
test: test_fernet test_compat
	@echo "=== C++ tests ==="
	@./test_fernet
	@echo ""
	@echo "=== Python cross-compatibility tests ==="
	@python3 test_compat.py

test_compat: test_fernet
	@python3 -c "from cryptography.fernet import Fernet" 2>/dev/null || \
	  { echo "Python 'cryptography' package required. Install: pip install cryptography"; exit 1; }

test_fernet: test_fernet.cpp fernet.h base64.h endian.h
	$(CXX) $(CXXFLAGS) test_fernet.cpp -o test_fernet $(LDFLAGS)

clean:
	@rm -f test_fernet
