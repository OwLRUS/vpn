cmake_minimum_required(VERSION 3.10)
project(CryptoApp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Находим OpenSSL
find_package(OpenSSL REQUIRED)

foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_SOURCE_DIR}/lib)
endforeach()

include_directories(${OPENSSL_INCLUDE_DIR})  # Добавляем include-директорию OpenSSL
include_directories(include/interfaces)
include_directories(include/modules/cert)
include_directories(include/modules/crypto)
include_directories(include/modules/sign)
include_directories(include/modules/hash)

add_executable(main src/main.cpp)

add_library(crypto SHARED src/modules/crypto/kuznechik.cpp include/modules/crypto/kuznechik.h)
add_library(hash SHARED src/modules/hash/streebog.cpp include/modules/hash/streebog.h)
add_library(sign SHARED src/modules/sign/signGOST.cpp include/modules/sign/signGOST.h)
add_library(cert SHARED src/modules/cert/x509gost.cpp include/modules/cert/x509gost.h)

target_include_directories(crypto PRIVATE include/interfaces)
target_include_directories(hash PRIVATE include/interfaces)
target_include_directories(sign PRIVATE include/interfaces)
target_include_directories(cert PRIVATE include/interfaces)

set_target_properties(crypto PROPERTIES OUTPUT_NAME "crypto")
set_target_properties(hash PROPERTIES OUTPUT_NAME "hash")
set_target_properties(sign PROPERTIES OUTPUT_NAME "sign")
set_target_properties(cert PROPERTIES OUTPUT_NAME "cert")

# Линкуем OpenSSL к библиотекам и исполняемому файлу
target_link_libraries(crypto PRIVATE OpenSSL::Crypto)
target_link_libraries(hash PRIVATE OpenSSL::Crypto)
target_link_libraries(sign PRIVATE OpenSSL::Crypto)
target_link_libraries(cert PRIVATE OpenSSL::Crypto)

target_link_libraries(main PRIVATE crypto hash sign cert)
