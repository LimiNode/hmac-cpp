cmake_minimum_required(VERSION 3.5)
project(hmac_cpp VERSION 0.6.0 LANGUAGES CXX)

option(HMACCPP_BUILD_EXAMPLES "Build the example program" OFF)
option(HMACCPP_BUILD_TESTS "Build the test suite" OFF)
option(HMACCPP_BUILD_BENCH "Build benchmarks" OFF)
option(HMACCPP_BUILD_SHARED "Build hmac_cpp as a shared library" OFF)
option(HMACCPP_ENABLE_MLOCK "Pin secret buffers in RAM using mlock/VirtualLock" ON)

include(CheckSymbolExists)
check_symbol_exists(explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)

if(HMACCPP_BUILD_SHARED)
    set(BUILD_SHARED_LIBS ON)
endif()

set(HMAC_SOURCES
    src/sha1.cpp
    src/sha256.cpp
    src/sha512.cpp
    src/hmac.cpp
    src/hmac_utils.cpp
    src/encoding.cpp
    src/memlock.cpp
)

set(HMAC_HEADERS
    include/hmac_cpp/api.hpp
    include/hmac_cpp/hmac.hpp
    include/hmac_cpp/hmac_utils.hpp
    include/hmac_cpp/sha1.hpp
    include/hmac_cpp/sha256.hpp
    include/hmac_cpp/sha512.hpp
    include/hmac_cpp/secure_buffer.hpp
    include/hmac_cpp/memlock.hpp
    include/hmac_cpp/page_lock_registry.hpp
    include/hmac_cpp/secret_string.hpp
    include/hmac_cpp/encoding.hpp
    include/hmac_cpp/version.hpp
)

add_library(hmac_cpp ${HMAC_SOURCES})
target_compile_features(hmac_cpp PUBLIC cxx_std_11)
target_include_directories(hmac_cpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(hmac_cpp PRIVATE HMAC_CPP_BUILD)
else()
target_compile_definitions(hmac_cpp PUBLIC HMAC_CPP_STATIC)
endif()

if(HMACCPP_ENABLE_MLOCK)
    target_compile_definitions(hmac_cpp PUBLIC HMAC_CPP_ENABLE_MLOCK)
endif()

if(HAVE_EXPLICIT_BZERO)
    target_compile_definitions(hmac_cpp PUBLIC HAVE_EXPLICIT_BZERO)
endif()

if(MSVC)
    target_compile_options(hmac_cpp PRIVATE /wd4251)
else()
    target_compile_options(hmac_cpp PRIVATE -fvisibility=hidden)
endif()

if(NOT TARGET hmac_cpp::hmac_cpp)
    add_library(hmac_cpp::hmac_cpp ALIAS hmac_cpp)
endif()

  if(HMACCPP_BUILD_EXAMPLES)
      add_executable(example example.cpp)
      target_link_libraries(example PRIVATE hmac_cpp)
      target_include_directories(example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

      add_executable(example_streaming example_streaming.cpp)
      target_link_libraries(example_streaming PRIVATE hmac_cpp)
      target_include_directories(example_streaming PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

      add_executable(example_pbkdf2 example_pbkdf2.cpp)
      target_link_libraries(example_pbkdf2 PRIVATE hmac_cpp)
      target_include_directories(example_pbkdf2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

      add_executable(example_encoding example_encoding.cpp)
      target_link_libraries(example_encoding PRIVATE hmac_cpp)
      target_include_directories(example_encoding PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

      add_executable(example_secret example_secret.cpp)
      target_link_libraries(example_secret PRIVATE hmac_cpp)
      target_include_directories(example_secret PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  endif()

include(CMakePackageConfigHelpers)
install(TARGETS hmac_cpp EXPORT hmac_cppTargets DESTINATION lib)
install(FILES ${HMAC_HEADERS} DESTINATION include/hmac_cpp)
install(EXPORT hmac_cppTargets
    FILE hmac_cppTargets.cmake
    NAMESPACE hmac_cpp::
    DESTINATION lib/cmake/hmac_cpp
)

configure_package_config_file(
    cmake/hmac_cppConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/hmac_cppConfig.cmake"
    INSTALL_DESTINATION lib/cmake/hmac_cpp
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/hmac_cppConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/hmac_cppConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/hmac_cppConfigVersion.cmake"
    DESTINATION lib/cmake/hmac_cpp
)

configure_file(cmake/hmac_cpp.pc.in "${CMAKE_CURRENT_BINARY_DIR}/hmac_cpp.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/hmac_cpp.pc" DESTINATION lib/pkgconfig)

if(HMACCPP_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(googletest)

    add_executable(test_secure_buffer test_secure_buffer.cpp)
    target_link_libraries(test_secure_buffer PRIVATE hmac_cpp gtest_main)
    target_include_directories(test_secure_buffer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    add_test(NAME test_secure_buffer COMMAND test_secure_buffer)

    add_executable(test_totp test_totp.cpp)
    target_link_libraries(test_totp PRIVATE hmac_cpp gtest_main)
    target_include_directories(test_totp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    add_test(NAME test_totp COMMAND test_totp)

    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        add_executable(test_all test_all.cpp)
        target_link_libraries(test_all PRIVATE hmac_cpp gtest_main OpenSSL::Crypto)
        target_include_directories(test_all PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        add_test(NAME test_all COMMAND test_all)
    else()
        message(STATUS "OpenSSL not found; skipping test_all")
    endif()
endif()

export(EXPORT hmac_cppTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/hmac_cppTargets.cmake"
    NAMESPACE hmac_cpp::
)
