# Shared header (common.h) and system libraries used by every module
add_library(common INTERFACE)
target_include_directories(common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(common INTERFACE gmp)
if(WIN32)
    target_link_libraries(common INTERFACE advapi32) # RtlGenRandom
    target_compile_definitions(common INTERFACE CC_BUILDING_SHARED) # dllexport CC_API functions
endif()

add_custom_target(tests)

# cc_module(<dir> [DEPS <module>...])
#   Builds the non-test sources of <dir> into a static library named <dir>, and
#   each <name>.test.c into a test executable registered with CTest.
#   List only direct dependencies: include paths and link dependencies are
#   propagated transitively, so building a target builds exactly what it needs.
function(cc_module name)
    cmake_parse_arguments(ARG "" "" "DEPS" ${ARGN})
    set(dir ${CMAKE_CURRENT_SOURCE_DIR}/${name})

    file(GLOB srcs CONFIGURE_DEPENDS ${dir}/*.c)
    file(GLOB test_srcs CONFIGURE_DEPENDS ${dir}/*.test.c)
    list(REMOVE_ITEM srcs ${test_srcs})

    add_library(${name} STATIC ${srcs})
    target_include_directories(${name} PUBLIC ${dir})
    target_link_libraries(${name} PUBLIC common ${ARG_DEPS})

    add_custom_target(tests_${name})
    add_dependencies(tests tests_${name})

    foreach(test_src ${test_srcs})
        get_filename_component(test_name ${test_src} NAME_WE) # enc.test.c -> enc
        set(target test_${name}_${test_name})

        add_executable(${target} ${test_src})
        target_link_libraries(${target} PRIVATE ${name})
        set_target_properties(${target} PROPERTIES
            OUTPUT_NAME ${test_name}.test
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/${name})
        add_dependencies(tests_${name} ${target})

        # Tests read their input files relative to the module directory
        add_test(NAME ${name}/${test_name} COMMAND ${target} WORKING_DIRECTORY ${dir})
        set_tests_properties(${name}/${test_name} PROPERTIES
            LABELS ${name}
            FAIL_REGULAR_EXPRESSION "FAIL")
    endforeach()
endfunction()

# Primitives
cc_module(misc)
cc_module(rng)
cc_module(md5)
cc_module(sha1)
cc_module(sha2)
cc_module(sha3)
cc_module(prime     DEPS rng)
cc_module(mgf       DEPS md5 sha1 sha2 sha3)

# Symmetric
cc_module(aes       DEPS misc)
cc_module(des       DEPS misc)
cc_module(mac       DEPS aes md5 sha1 sha2 sha3 misc)

# Public key (finite field)
cc_module(rsa       DEPS mgf prime rng sha2 misc)
cc_module(elgamal   DEPS prime rng sha2 misc)
cc_module(dsa       DEPS prime rng sha2 sha3 misc)
cc_module(dh        DEPS elgamal rng misc)

# Public key (elliptic curve)
cc_module(ec        DEPS sha2 sha3 misc)
cc_module(ecelgamal DEPS ec rng sha2 sha3 misc)
cc_module(ecdsa     DEPS ec rng sha2 sha3 misc)
cc_module(ecdh      DEPS ecelgamal rng misc)

# Public API: a single shared library exporting the cc_* functions of include/cryptocalc.h
file(GLOB api_srcs CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/api/*.c)
file(GLOB api_test_srcs CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/api/*.test.c)
list(REMOVE_ITEM api_srcs ${api_test_srcs})

# cc_strerror is not called by the API itself, so it would not be pulled from libmisc
add_library(cryptocalc SHARED ${api_srcs} ${CMAKE_CURRENT_SOURCE_DIR}/misc/status.c)
target_include_directories(cryptocalc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(cryptocalc PRIVATE misc rng md5 sha1 sha2 sha3 prime mgf aes des mac rsa elgamal dsa dh ec ecelgamal ecdsa ecdh)
target_compile_definitions(cryptocalc INTERFACE $<$<BOOL:${WIN32}>:CC_USING_SHARED>)

# CMake repeats static libraries on the link line to satisfy their order; Apple's linker warns about it
include(CheckLinkerFlag)
check_linker_flag(C "LINKER:-no_warn_duplicate_libraries" CC_LINKER_NO_DUP_WARNING)
if(CC_LINKER_NO_DUP_WARNING)
    target_link_options(cryptocalc PRIVATE "LINKER:-no_warn_duplicate_libraries")
endif()
set_target_properties(cryptocalc PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# The API test links only the shared library, so it can only use exported functions
add_custom_target(tests_api)
add_dependencies(tests tests_api)
foreach(test_src ${api_test_srcs})
    get_filename_component(test_name ${test_src} NAME_WE)
    set(target test_api_${test_name})
    add_executable(${target} ${test_src})
    target_link_libraries(${target} PRIVATE cryptocalc)
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME ${test_name}.test
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/api)
    add_dependencies(tests_api ${target})
    add_test(NAME api/${test_name} COMMAND ${target} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set_tests_properties(api/${test_name} PROPERTIES LABELS api FAIL_REGULAR_EXPRESSION "FAIL")
endforeach()

install(TARGETS cryptocalc)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/cryptocalc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
