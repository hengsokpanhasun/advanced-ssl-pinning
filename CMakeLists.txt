cmake_minimum_required(VERSION 3.10)
project(advanced_ssl_pinning C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra)
endif()

# --- library ---
add_library(aspin STATIC
  src/sha256.c
  src/hmac_sha256.c
  src/pins.c
  src/aspin.c)
target_include_directories(aspin PUBLIC include PRIVATE src)

# --- example + tool ---
add_executable(aspin_demo examples/demo.c)
target_link_libraries(aspin_demo aspin)
target_include_directories(aspin_demo PRIVATE src tests)

add_executable(gen_pins tools/gen_pins.c)
target_link_libraries(gen_pins aspin)
target_include_directories(gen_pins PRIVATE src)

# --- tests ---
enable_testing()

add_executable(test_sha256 tests/test_sha256.c)
target_link_libraries(test_sha256 aspin)
target_include_directories(test_sha256 PRIVATE src)
add_test(NAME sha256 COMMAND test_sha256)

add_executable(test_pinning tests/test_pinning.c)
target_link_libraries(test_pinning aspin)
target_include_directories(test_pinning PRIVATE src tests)
add_test(NAME pinning COMMAND test_pinning)
