cmake_minimum_required(VERSION 3.22)
project(transferchain_argon2 C CXX)
set(ARGON "${CMAKE_CURRENT_LIST_DIR}/../../ios/vendor/argon2")
# Android and iOS share the same pinned reference C source.
# A new kernel must pass equivalent vectors for all three variants.
add_library(transferchain_argon2 SHARED
    Argon2Jni.cpp Argon2JniVerification.cpp
    ${ARGON}/src/argon2.c ${ARGON}/src/core.c ${ARGON}/src/encoding.c
    ${ARGON}/src/ref.c ${ARGON}/src/thread.c ${ARGON}/src/blake2/blake2b.c)
target_include_directories(transferchain_argon2 PRIVATE ${ARGON}/include)
target_compile_options(transferchain_argon2 PRIVATE -O2 -fstack-protector-strong)
target_link_options(transferchain_argon2 PRIVATE -Wl,-z,max-page-size=16384 -Wl,-z,relro,-z,now)
