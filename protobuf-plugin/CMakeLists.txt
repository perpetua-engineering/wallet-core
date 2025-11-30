# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017 Trust Wallet.

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(TrustWalletCoreProtobufPlugin)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if("$ENV{PREFIX}" STREQUAL "")
    set(PREFIX "${CMAKE_SOURCE_DIR}/../build/local")
else()
    set(PREFIX "$ENV{PREFIX}")
endif()

find_package(Protobuf CONFIG REQUIRED PATH ${PREFIX}/lib/pkgconfig)

add_executable(protoc-gen-c-typedef c_typedef.cc)
target_link_libraries(protoc-gen-c-typedef protobuf::libprotobuf protobuf::libprotoc)

add_executable(protoc-gen-swift-typealias swift_typealias.cc)
target_link_libraries(protoc-gen-swift-typealias protobuf::libprotobuf protobuf::libprotoc)

install(TARGETS protoc-gen-c-typedef protoc-gen-swift-typealias DESTINATION bin)
