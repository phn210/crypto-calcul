from Cython.Build import cythonize
from Cython.Distutils import build_ext
from multiprocessing import Process, freeze_support, set_start_method
from setuptools import setup, Extension
import os, re

# os.environ["CC"] = "clang"
SRC_DIR = "src/backend"
OBJ_DIR = "obj"
BUILD_DIR = "build"
WRAPPER_DIR = f"src/backend/wrappers"
LIB_NAME = WRAPPER_DIR.split("/")[-1]

def wrap_c_lib():
    class CustomBuildExtension(build_ext):
        def run(self):
            self.build_lib = BUILD_DIR
            self.inplace = False
            super().run()
            
    def get_deps(directory):
        try:
            with open(f"{directory}/Makefile.env", "r") as file:
                content = file.read()
            match = re.search(r'^TEST_DEPS\s*=\s*(.*?)(?<!\\)\n', content, re.DOTALL | re.MULTILINE)
            if match:
                deps = match.group(1).replace("\\", "").split()
                return [f"{OBJ_DIR}/{dep}" for dep in deps]
            else:
                return []
        except Exception as e:
            return []

    def get_extension(module):
        name = f'{LIB_NAME}.{module}'
        sources = [f'{WRAPPER_DIR}/{module}/__init__.py']
        objects = []
        if module not in ["enums", "gmp"]:
            objects += get_deps(f'{SRC_DIR}/{module}') + [
                f'{OBJ_DIR}/{module}/{f.replace(".c", ".o")}' for f in os.listdir(os.path.join(SRC_DIR, module)) \
                if f.endswith(".c") and not f.endswith(".test.c")
            ]
        include_dirs = [f'{SRC_DIR}'] + list(set(
            [f'{SRC_DIR}/{"/".join(file.split("/")[1:-1])}' for file in objects]
        ))
        
        return Extension(
            name,
            sources=sources,
            extra_objects=objects,
            include_dirs=include_dirs,
            libraries=["gmp"],
            # extra_compile_args=["-fsanitize=address", "-fno-omit-frame-pointer", "-g"],
            # extra_link_args=["-fsanitize=address", "-shared-libasan"],
        )

    cython_directives = {
        "boundscheck": "False",
        "wraparound": "False",
        "cdivision": "True",
        "language_level": "3",
        "emit_code_comments": "False",
    }

    excludes = ["__pycache__"]
    modules = [item for item in os.listdir(WRAPPER_DIR) if os.path.isdir(os.path.join(WRAPPER_DIR, item)) and item not in excludes]
    extensions = [get_extension(module) for module in modules]
    
    # Cython setup
    setup(
        name="wrappers",
        ext_modules=cythonize(
            extensions,
            compiler_directives=cython_directives,
            quiet=True
        ),
        cmdclass={'build_ext': CustomBuildExtension},
        zip_safe=False,
    )

if __name__ == '__main__':
    freeze_support()
    set_start_method('spawn')
    p = Process(target=wrap_c_lib)
    p.start()