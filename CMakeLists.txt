cmake_minimum_required(VERSION 3.10)
project(CryptoApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.lib")

foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/lib)
endforeach()

include_directories(${OPENSSL_INCLUDE_DIR})  # Добавляем include-директорию OpenSSL
include_directories(include/interfaces)

add_executable(main src/main.cpp)

add_library(crypto SHARED src/modules/crypto/kuznechik.cpp)
add_library(hash SHARED src/modules/hash/streebog.cpp)
add_library(sign SHARED src/modules/sign/signGOST.cpp)
add_library(cert SHARED src/modules/cert/x509gost.cpp)

target_include_directories(crypto PRIVATE include/interfaces)
target_include_directories(hash PRIVATE include/interfaces)
target_include_directories(sign PRIVATE include/interfaces)
target_include_directories(cert PRIVATE include/interfaces)

set_target_properties(crypto PROPERTIES OUTPUT_NAME "crypto")
set_target_properties(hash PROPERTIES OUTPUT_NAME "hash")
set_target_properties(sign PROPERTIES OUTPUT_NAME "sign")
set_target_properties(cert PROPERTIES OUTPUT_NAME "cert")

# Находим OpenSSL
find_package(OpenSSL REQUIRED)

# Линкуем OpenSSL к библиотекам и исполняемому файлу
target_link_libraries(main ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(crypto ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(hash ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(sign ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(cert ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})