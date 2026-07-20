cmake_minimum_required(VERSION 3.20)
project(bambu_keysaver_win CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to an optimized build; the factor-recovery search is compute-heavy.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(MSVC)
  add_compile_options(/EHsc /W3)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# ---------------------------------------------------------------------------
# keysaver_core: the OS-independent key-recovery core, compiled under MSVC.
# Reconstruction needs no third-party libraries.
# ---------------------------------------------------------------------------
add_library(keysaver_core STATIC
  ${SRC}/reconstruct.cpp
  ${SRC}/bigint.cpp
  ${SRC}/envelope.cpp
  ${SRC}/version.cpp
  ${SRC}/vendored/BigIntModExp.cpp
)
target_include_directories(keysaver_core PUBLIC ${SRC})

# NOTE: output.cpp (PEM writing) is intentionally NOT compiled here — it needs
# OpenSSL and pulls POSIX logging. The pipeline emits the recovered key as hex
# components (self-validated); convert to PEM with the openssl CLI if desired.

# ---------------------------------------------------------------------------
# Phase 0 verification: round-trip a synthetic RSA-2048 key through the core.
# ---------------------------------------------------------------------------
add_executable(core_selftest core_selftest.cpp)
target_link_libraries(core_selftest PRIVATE keysaver_core)

# ---------------------------------------------------------------------------
# Phase 1: minimal loader host + verification-faking shim (Windows only).
# ---------------------------------------------------------------------------
if(WIN32)
  include(FetchContent)
  FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG        master
  )
  FetchContent_MakeAvailable(minhook)

  add_library(verify_fake STATIC shim/verify_fake.cpp)
  target_include_directories(verify_fake PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(verify_fake PUBLIC minhook crypt32 wintrust)

  # open-bamboo-networking's get_app_cert client (obn::appcert::fetch) + a WinHTTP
  # transport shim, so bambu_host retrieves the app cert from the cloud instead of
  # memory-scanning. Uses the OpenSSL already on the machine (libcrypto only).
  set(OBN ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/open-bamboo-networking)
  if(NOT OPENSSL_ROOT_DIR)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
  endif()
  find_package(OpenSSL REQUIRED)

  add_executable(fake_broker2 broker/fake_broker2.cpp)
  target_link_libraries(fake_broker2 PRIVATE
    ws2_32
    crypt32
    OpenSSL::SSL
    OpenSSL::Crypto
    ${OPENSSL_STATIC_DEPENDENCIES})
  set_target_properties(fake_broker2 PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/broker")

  add_executable(bambu_host
    host/main.cpp
    host/known_scan.cpp
    host/plugin_fetch.cpp
    host/logkey.cpp
    host/verdict_flip.cpp
    host/cloud_tap.cpp
    host/rng_tap.cpp
    host/aes_tap.cpp
    host/instr_cb.cpp
    host/app_key_sweep.cpp
    host/death_diag.cpp
    host/dump_regions.cpp
    host/lan_discover.cpp
    host/app_cert_fetch.cpp
    host/obn_http_winhttp.cpp
    ${OBN}/src/app_cert.cpp
    ${OBN}/src/json_lite.cpp
    ${OBN}/src/log.cpp
    ${OBN}/src/os_compat.cpp
    ${SRC}/bambu/BambuNetworkingPluginHandle.cpp)
  target_include_directories(bambu_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${SRC} ${OBN}/include)
  target_compile_definitions(bambu_host PRIVATE OBN_VERSION_STRING="02.07.01.99")
  target_link_libraries(bambu_host PRIVATE verify_fake keysaver_core ws2_32 psapi bcrypt ncrypt OpenSSL::Crypto winhttp)

  # Standalone AES-128-ECB decoder for the plugin's debug_network_*.log.enc
  # numeric log. Own main().
  add_executable(declog host/declog.cpp)
  target_link_libraries(declog PRIVATE bcrypt)

  # ---------------------------------------------------------------------------
  # app_key_selftest: OFFLINE round-trip for app_key_sweep -- recover p,q from
  # raw memory buffers given a caller-supplied RSA-2048 modulus (the cloud "app
  # key"). Synthetic key, no plugin. Own main(). Separate from bambu_host so its
  # source list never touches the live-capture host target.
  add_executable(app_key_selftest host/app_key_sweep.cpp host/app_key_selftest.cpp)
  target_include_directories(app_key_selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${SRC})
  target_link_libraries(app_key_selftest PRIVATE keysaver_core)
endif()
