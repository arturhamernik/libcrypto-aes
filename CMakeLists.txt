project(LibcryptoAES)

cmake_minimum_required(VERSION 3.24)
project(LibcryptoAES)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++ -static-libgcc")

set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_SSL_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib")
set(OPENSSL_CRYPTO_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib")

find_package(OpenSSL REQUIRED)

include_directories("C:/Program Files/OpenSSL-Win64/include")

add_executable(LibcryptoAES main.c)
add_executable(AES_128 AES_128.c)
add_executable(AES_192 AES_192.c)
add_executable(AES_256 AES_256.c)

target_link_libraries(LibcryptoAES "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib")
target_link_libraries(AES_128 "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib")
target_link_libraries(AES_192 "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib")
target_link_libraries(AES_256 "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MTd/libcrypto.lib")