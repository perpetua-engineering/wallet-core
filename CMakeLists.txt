# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017 Trust Wallet.

cmake_minimum_required(VERSION 3.18 FATAL_ERROR)

project(TrustWalletCore)

if (NOT ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
    message(FATAL_ERROR "You should use clang compiler")
endif ()

# The Apple RNG override is implemented in Objective-C so it can call the
# Security framework directly.  Without enabling the language here,
# swift/Sources/SecRandom.m is never part of the native WalletCore archive.
#
# trezor-crypto/crypto/rand.c deliberately compiles to nothing on Apple, so
# there is no longer a weak /dev/urandom fallback to lose to: an Apple build
# that omits this file fails to link with unresolved random32/random_buffer.
if (APPLE)
    enable_language(OBJC)
    set(WALLET_CORE_APPLE_RNG_PROVIDER
        ${CMAKE_CURRENT_SOURCE_DIR}/swift/Sources/SecRandom.m)
    if (NOT EXISTS ${WALLET_CORE_APPLE_RNG_PROVIDER})
        message(FATAL_ERROR
            "Apple RNG provider missing: ${WALLET_CORE_APPLE_RNG_PROVIDER}")
    endif ()
endif ()

if ("$ENV{PREFIX}" STREQUAL "")
    set(PREFIX "${CMAKE_SOURCE_DIR}/build/local")
else ()
    set(PREFIX "$ENV{PREFIX}")
endif ()

include(GNUInstallDirs)
include(cmake/StandardSettings.cmake)
include(cmake/CompilerWarnings.cmake)
include(cmake/StaticAnalyzers.cmake)
include(cmake/FindHostPackage.cmake)

set(WALLET_CORE_RS_TARGET_DIR ${CMAKE_SOURCE_DIR}/rust/target)
add_library(${PROJECT_NAME}_INTERFACE INTERFACE)
target_include_directories(${PROJECT_NAME}_INTERFACE INTERFACE ${PREFIX}/include)
target_link_directories(${PROJECT_NAME}_INTERFACE INTERFACE ${PREFIX}/lib)
target_link_directories(${PROJECT_NAME}_INTERFACE INTERFACE ${WALLET_CORE_RS_TARGET_DIR}/release)
set_project_warnings(${PROJECT_NAME}_INTERFACE)

add_subdirectory(trezor-crypto)
set(WALLET_CORE_RS_LIB libwallet_core_rs.a)

set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/release/${WALLET_CORE_RS_LIB})
if (TW_COMPILE_WASM)
    message(STATUS "Wasm build enabled")
    set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/wasm32-unknown-emscripten/release/${WALLET_CORE_RS_LIB})
    add_subdirectory(wasm)
endif ()

find_host_package(Boost REQUIRED)

include(ExternalProject)

# Dependencies
include(cmake/Protobuf.cmake)

# Source files
if (${ANDROID})
    message("Configuring for Android JNI")
    file(GLOB_RECURSE core_sources src/*.c src/*.cc src/*.cpp src/*.h jni/cpp/*.cpp jni/cpp/*.h)
    # Keep the security-critical RNG provider in its own object even when the
    # rest of WalletCore uses a unity build. The Android artifact verifier can
    # then prove exact object ownership of random32/random_buffer.
    set_source_files_properties(jni/cpp/Random.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
    if (${KOTLIN})
        file(GLOB_RECURSE specific_sources
                jni/kotlin/*.h
                jni/kotlin/*.c
                kotlin/wallet-core-kotlin/src/commonAndroidJvmMain/cpp/generated/*.h
                kotlin/wallet-core-kotlin/src/commonAndroidJvmMain/cpp/generated/*.c
                )
    else ()
        file(GLOB_RECURSE specific_sources jni/android/*.h jni/android/*.c)
    endif ()
    set(sources ${core_sources} ${specific_sources})
    add_library(TrustWalletCore SHARED ${sources} ${PROTO_SRCS} ${PROTO_HDRS})
    find_library(log-lib log)
    if (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
        set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/aarch64-linux-android/release/${WALLET_CORE_RS_LIB})
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86")
        set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/i686-linux-android/release/${WALLET_CORE_RS_LIB})
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
        set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/armv7-linux-androideabi/release/${WALLET_CORE_RS_LIB})
    elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "x86_64")
        set(WALLET_CORE_BINDGEN ${WALLET_CORE_RS_TARGET_DIR}/x86_64-linux-android/release/${WALLET_CORE_RS_LIB})
    endif ()
    target_link_libraries(TrustWalletCore PUBLIC ${WALLET_CORE_BINDGEN} ${PROJECT_NAME}_INTERFACE PRIVATE TrezorCrypto protobuf ${log-lib} Boost::boost)
elseif (${TW_COMPILE_JAVA})
    message("Configuring for JNI")
    file(GLOB_RECURSE core_sources src/*.c src/*.cc src/*.cpp src/*.h jni/cpp/*.cpp jni/cpp/*.h)
    if (${TW_COMPILE_KOTLIN})
        file(GLOB_RECURSE specific_sources
                jni/kotlin/*.h
                jni/kotlin/*.c
                kotlin/wallet-core-kotlin/src/commonAndroidJvmMain/cpp/generated/*.h
                kotlin/wallet-core-kotlin/src/commonAndroidJvmMain/cpp/generated/*.c
                )
    else ()
        file(GLOB_RECURSE specific_sources jni/android/*.h jni/android/*.c)
    endif ()
    set(sources ${core_sources} ${specific_sources})
    if (APPLE)
        # A JNI build on an Apple host is an Apple build: rand.c contributes no
        # RNG definitions there, so without the provider this target no longer
        # links at all.
        list(APPEND sources ${WALLET_CORE_APPLE_RNG_PROVIDER})
    endif ()
    add_library(TrustWalletCore SHARED ${sources} ${PROTO_SRCS} ${PROTO_HDRS})
    find_package(JNI REQUIRED)
    target_include_directories(TrustWalletCore PRIVATE ${JNI_INCLUDE_DIRS})
    target_link_libraries(TrustWalletCore PUBLIC ${WALLET_CORE_BINDGEN} ${PROJECT_NAME}_INTERFACE PRIVATE TrezorCrypto protobuf Boost::boost)
elseif (${FLUTTER})
    message("Configuring for Flutter")
    file(GLOB_RECURSE sources src/*.c src/*.cc src/*.cpp src/*.h)
    if (APPLE)
        list(APPEND sources ${WALLET_CORE_APPLE_RNG_PROVIDER})
    endif ()
    add_library(TrustWalletCore SHARED ${sources} ${PROTO_SRCS} ${PROTO_HDRS})
    target_link_libraries(TrustWalletCore PUBLIC ${WALLET_CORE_BINDGEN} ${PROJECT_NAME}_INTERFACE PRIVATE TrezorCrypto protobuf Boost::boost)
else ()
    message("Configuring standalone")
    file(GLOB_RECURSE sources src/*.c src/*.cc src/*.cpp src/*.h)
    if (APPLE)
        list(APPEND sources ${WALLET_CORE_APPLE_RNG_PROVIDER})
    endif ()
    add_library(TrustWalletCore STATIC ${sources} ${PROTO_SRCS} ${PROTO_HDRS})
    target_link_libraries(TrustWalletCore PUBLIC ${WALLET_CORE_BINDGEN} ${PROJECT_NAME}_INTERFACE PRIVATE TrezorCrypto protobuf Boost::boost)
endif ()

if (APPLE)
    # SecRandom.m references _SecRandomCopyBytes / _kSecRandomDefault, so every
    # Apple configuration needs Security.framework. The SHARED variants
    # (TW_COMPILE_JAVA on an Apple host, FLUTTER) resolve it at their own link
    # step and fail outright without it; the standalone STATIC archive defers
    # resolution to its consumer, where this records the usage requirement.
    target_link_libraries(TrustWalletCore PRIVATE "-framework Security")
endif ()

if (TW_CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_enable_coverage(TrustWalletCore)
endif ()

if (TW_CLANG_ASAN)
    target_enable_asan(TrustWalletCore)
endif ()

# Define headers for this library. PUBLIC headers are used for compiling the
# library, and will be added to consumers' build paths.
target_include_directories(TrustWalletCore
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/jni/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/build/local/include
        )

if (TW_UNIT_TESTS)
    add_subdirectory(tests)
endif ()

if (TW_BUILD_EXAMPLES)
    add_subdirectory(walletconsole/lib)
    add_subdirectory(walletconsole)
endif ()

if (TW_ENABLE_PVS_STUDIO)
    tw_add_pvs_studio_target(TrustWalletCore)
endif ()

if (TW_ENABLE_CLANG_TIDY)
    tw_add_clang_tidy_target(TrustWalletCore)
endif ()

if (TW_UNITY_BUILD)
    set_target_properties(TrustWalletCore PROPERTIES UNITY_BUILD ON)

    file(GLOB_RECURSE PROTOBUF_SOURCE_FILES CONFIGURE_DEPENDS src/Cosmos/Protobuf/*.pb.cc src/Hedera/Protobuf/*.pb.cc src/proto/*.pb.cc)
    foreach (file ${PROTOBUF_SOURCE_FILES})
        set_property(SOURCE ${file} PROPERTY SKIP_UNITY_BUILD_INCLUSION ON)
    endforeach ()
    message(STATUS "Unity build activated")
endif ()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/swift/cpp.xcconfig.in ${CMAKE_CURRENT_SOURCE_DIR}/swift/cpp.xcconfig @ONLY)

install(TARGETS TrustWalletCore
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )

install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/WalletCore
        FILES_MATCHING PATTERN "*.h"
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
