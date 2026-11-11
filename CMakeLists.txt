cmake_minimum_required(VERSION 3.16)
project(overlay_lab CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
add_compile_options(-Wall -Wextra -Wpedantic)

option(OL_SANITIZE "Build with ASan + UBSan" OFF)
if(OL_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_executable(vxlan_tun src/vxlan_tun.cpp)
add_executable(vxlan_codec src/vxlan_codec.cpp)
