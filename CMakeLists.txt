cmake_minimum_required(VERSION 3.10)
project(vanitygen LANGUAGES CXX)

if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Поиск зависимостей
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(SECP256K1 REQUIRED IMPORTED_TARGET libsecp256k1)

add_executable(vanitygen src/main.cpp)

target_include_directories(vanitygen PRIVATE
    ${SECP256K1_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(vanitygen PRIVATE
    PkgConfig::SECP256K1
    OpenSSL::Crypto
    Threads::Threads
)