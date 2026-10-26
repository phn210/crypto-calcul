find_package(Python3 COMPONENTS Interpreter Development.Module)
if(Python3_FOUND)
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import Cython"
        RESULT_VARIABLE cython_missing
        OUTPUT_QUIET ERROR_QUIET)
endif()
if(NOT Python3_FOUND OR cython_missing)
    message(WARNING "Python 3 or Cython not found: skipping the wrappers (pass -DPython3_EXECUTABLE=.venv/bin/python3)")
    return()
endif()

set(CYTHON_DIRECTIVES "boundscheck=False,wraparound=False,cdivision=True,language_level=3,emit_code_comments=False")

# Wrappers cimport each other, so any .pxd change re-cythonizes all of them
file(GLOB pxd_files CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.pxd ${CMAKE_CURRENT_SOURCE_DIR}/*/*.pxd)

add_custom_target(wrappers ALL)

# cc_wrapper(<name> <library>)
#   Cythonizes wrappers/<name>/__init__.py into the extension module wrappers.<name>
#   (build/wrappers/<name>.<soabi>.so), linked against the C library <library>.
function(cc_wrapper name lib)
    set(src ${CMAKE_CURRENT_SOURCE_DIR}/${name}/__init__.py)
    set(c_file ${CMAKE_CURRENT_BINARY_DIR}/${name}.c)

    add_custom_command(
        OUTPUT ${c_file}
        COMMAND ${Python3_EXECUTABLE} -m cython -3 --fast-fail -X ${CYTHON_DIRECTIVES}
                -I ${CMAKE_CURRENT_SOURCE_DIR}/.. -o ${c_file} ${src}
        DEPENDS ${src} ${pxd_files}
        COMMENT "Cythonizing wrappers.${name}"
        VERBATIM)

    Python3_add_library(wrapper_${name} MODULE WITH_SOABI ${c_file})
    target_link_libraries(wrapper_${name} PRIVATE ${lib})
    set_target_properties(wrapper_${name} PROPERTIES
        OUTPUT_NAME ${name}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/wrappers)
    add_dependencies(wrappers wrapper_${name})
endfunction()

cc_wrapper(enums     common)
cc_wrapper(gmp       common)
cc_wrapper(rng       rng)
cc_wrapper(prime     prime)
cc_wrapper(md5       md5)
cc_wrapper(sha1      sha1)
cc_wrapper(sha2      sha2)
cc_wrapper(sha3      sha3)
cc_wrapper(aes       aes)
cc_wrapper(des       des)
cc_wrapper(mac       mac)
cc_wrapper(rsa       rsa)
cc_wrapper(elgamal   elgamal)
cc_wrapper(dsa       dsa)
cc_wrapper(dh        dh)
cc_wrapper(ec        ec)
cc_wrapper(ecelgamal ecelgamal)
cc_wrapper(ecdsa     ecdsa)
cc_wrapper(ecdh      ecdh)
