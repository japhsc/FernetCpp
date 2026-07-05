cmake_minimum_required(VERSION 3.15)
project(fernet VERSION 2.0.0 LANGUAGES CXX)

# FernetCpp is a header-only library requiring C++17 and Crypto++
add_library(fernet INTERFACE)
target_include_directories(fernet INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(fernet INTERFACE cxx_std_17)
target_link_libraries(fernet INTERFACE cryptopp)

install(
    FILES base64.h endian.h fernet.h
    DESTINATION include/fernet
)
