# Shared header (common.h) and system libraries used by every module
add_library(common INTERFACE)
target_include_directories(common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(common INTERFACE gmp)
if(WIN32)
    target_link_libraries(common INTERFACE advapi32) # RtlGenRandom
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
cc_module(ec        DEPS misc)
cc_module(ecelgamal DEPS ec rng sha2 sha3 misc)
cc_module(ecdsa     DEPS ec rng sha2 sha3 misc)
cc_module(ecdh      DEPS ecelgamal rng misc)
