cmake_minimum_required(VERSION 3.20)
project(crypto-calcul LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Options
option(CC_BUILD_WRAPPERS "Build the Cython wrappers used by the GUI" ON)
option(CC_SANITIZE "Build with sanitizers" OFF)
set(CC_SANITIZER "address" CACHE STRING "Sanitizer used when CC_SANITIZE is ON: address, leak, thread, undefined")

# Compiler flags
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # static libs are linked into Python extensions
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-Wall -Wextra)

if(WIN32)
    add_compile_definitions(WINDOWS_H)
endif()

if(CC_SANITIZE)
    add_compile_options(-fsanitize=${CC_SANITIZER} -fsanitize-recover=${CC_SANITIZER} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${CC_SANITIZER} -fsanitize-recover=${CC_SANITIZER})
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        # Needed to preload the sanitizer runtime into Python (see src/frontend/debug.sh)
        add_link_options(-shared-libsan)
    endif()
endif()

# GMP
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(GMP QUIET IMPORTED_TARGET gmp)
endif()
add_library(gmp INTERFACE)
if(TARGET PkgConfig::GMP)
    target_link_libraries(gmp INTERFACE PkgConfig::GMP)
else()
    find_path(GMP_INCLUDE_DIR gmp.h REQUIRED)
    find_library(GMP_LIBRARY gmp REQUIRED)
    target_include_directories(gmp INTERFACE ${GMP_INCLUDE_DIR})
    target_link_libraries(gmp INTERFACE ${GMP_LIBRARY})
endif()

enable_testing()
add_subdirectory(src/backend)

if(CC_BUILD_WRAPPERS)
    add_subdirectory(src/backend/wrappers)
endif()
