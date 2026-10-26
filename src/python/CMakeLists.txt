# Python package `cryptocalc`: cffi bindings to libcryptocalc plus a thin Python layer.
# In a normal build the package is assembled in build/python (PYTHONPATH=build/python);
# under scikit-build-core (pip install .) it is installed into the wheel instead.

find_package(Python3 COMPONENTS Interpreter Development.Module)
if(Python3_FOUND)
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -c "import cffi"
        RESULT_VARIABLE cffi_missing
        OUTPUT_QUIET ERROR_QUIET)
endif()
if(NOT Python3_FOUND OR cffi_missing)
    message(WARNING "Python 3 or cffi not found: skipping the Python package (pass -DPython3_EXECUTABLE=.venv/bin/python3)")
    return()
endif()

set(header ${PROJECT_SOURCE_DIR}/src/backend/include/cryptocalc.h)
set(native_c ${CMAKE_CURRENT_BINARY_DIR}/_native.c)
set(package_dir ${CMAKE_BINARY_DIR}/python/cryptocalc)

add_custom_command(
    OUTPUT ${native_c}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/build_ffi.py ${header} ${native_c}
    DEPENDS ${header} ${CMAKE_CURRENT_SOURCE_DIR}/build_ffi.py
    COMMENT "Generating cffi bindings from cryptocalc.h"
    VERBATIM)

Python3_add_library(cryptocalc_native MODULE WITH_SOABI ${native_c})
target_link_libraries(cryptocalc_native PRIVATE cryptocalc)
# Generated code: warnings there are not actionable
target_compile_options(cryptocalc_native PRIVATE -w)
set_target_properties(cryptocalc_native PROPERTIES
    OUTPUT_NAME _native
    LIBRARY_OUTPUT_DIRECTORY ${package_dir}
    RUNTIME_OUTPUT_DIRECTORY ${package_dir}
    # The shared library is installed next to the extension
    INSTALL_RPATH "$<IF:$<BOOL:${APPLE}>,@loader_path,$ORIGIN>")

# Copy the Python sources next to the extension so build/python is importable
file(GLOB py_sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/cryptocalc/*.py)
set(py_outputs)
foreach(src ${py_sources})
    get_filename_component(name ${src} NAME)
    add_custom_command(
        OUTPUT ${package_dir}/${name}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${src} ${package_dir}/${name}
        DEPENDS ${src}
        VERBATIM)
    list(APPEND py_outputs ${package_dir}/${name})
endforeach()
add_custom_target(cryptocalc_py ALL DEPENDS ${py_outputs})

add_custom_target(python ALL DEPENDS cryptocalc_native cryptocalc_py)

# `make test` and `make test_python` rebuild the package before running its tests
add_custom_target(tests_python DEPENDS python)
add_dependencies(tests tests_python)

if(WIN32)
    # No rpath on Windows: the DLL must sit next to the extension
    add_custom_command(TARGET cryptocalc_native POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:cryptocalc> ${package_dir}
        VERBATIM)
endif()

if(SKBUILD)
    # The Python sources are added by scikit-build-core (wheel.packages)
    install(TARGETS cryptocalc_native LIBRARY DESTINATION cryptocalc RUNTIME DESTINATION cryptocalc)
    install(TARGETS cryptocalc LIBRARY DESTINATION cryptocalc RUNTIME DESTINATION cryptocalc)
endif()

if(CC_BUILD_TESTS)
    add_test(NAME python/unittest
        COMMAND ${Python3_EXECUTABLE} -m unittest discover -s ${CMAKE_CURRENT_SOURCE_DIR}/tests -t ${CMAKE_CURRENT_SOURCE_DIR}/tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set(test_env "PYTHONPATH=${CMAKE_BINARY_DIR}/python")

    # Python is not instrumented, so an AddressSanitizer runtime must be preloaded into it
    if(CC_SANITIZE AND CC_SANITIZER MATCHES "address")
        if(APPLE)
            set(asan_runtime libclang_rt.asan_osx_dynamic.dylib)
            set(preload_var DYLD_INSERT_LIBRARIES)
        elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
            set(asan_runtime libclang_rt.asan-${CMAKE_SYSTEM_PROCESSOR}.so)
            set(preload_var LD_PRELOAD)
        else()
            set(asan_runtime libasan.so)
            set(preload_var LD_PRELOAD)
        endif()
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} -print-file-name=${asan_runtime}
            OUTPUT_VARIABLE asan_path OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(IS_ABSOLUTE "${asan_path}" AND EXISTS "${asan_path}")
            list(APPEND test_env "${preload_var}=${asan_path}" "ASAN_OPTIONS=detect_leaks=0")
        else()
            message(WARNING "AddressSanitizer runtime not found: the Python tests are not run in this build")
            set(test_env "")
        endif()
    endif()

    if(test_env)
        set_tests_properties(python/unittest PROPERTIES LABELS python ENVIRONMENT "${test_env}")
    else()
        set_tests_properties(python/unittest PROPERTIES LABELS python DISABLED TRUE)
    endif()
endif()
