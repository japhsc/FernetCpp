.PHONY: format format-check

# Format all source files in-place
format:
	@clang-format -i *.h

# Check if files are correctly formatted (for CI)
format-check:
	@clang-format --dry-run --Werror *.h && echo "All files correctly formatted."
