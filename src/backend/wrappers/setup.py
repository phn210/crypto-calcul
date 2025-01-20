from Cython.Build import cythonize
from Cython.Distutils import build_ext
from dotenv import load_dotenv, get_key
from multiprocessing import Process, freeze_support, set_start_method
from setuptools import Extension, setup, find_packages
import logging, os, platform

logging.getLogger("dotenv").setLevel(logging.ERROR)
load_dotenv()

SRC_DIR = os.environ["C_SRC_DIR"]
OBJ_DIR = os.environ["ROOT_OBJ_DIR"]
BUILD_DIR = os.environ["ROOT_BIN_DIR"]
WRAPPER_DIR = f"{SRC_DIR}/wrappers"
LIB_NAME = WRAPPER_DIR.split("/")[-1]

CFLAGS = os.environ["CFLAGS"].split(" ")
LDFLAGS = os.environ["LDFLAGS"].split(" ")

if os.environ["APP_ENV"] == "debug":
    os.environ["CC"] = "clang"
    SANITIZER = os.environ["SANITIZER"]
    CFLAGS += os.environ["SAN_CFLAGS"].replace("$(SANITIZER)", SANITIZER).split(" ")
    LDFLAGS += os.environ["SAN_LDFLAGS"].replace("$(SANITIZER)", SANITIZER).split(" ")

if (platform.system() == 'Windows'):
    CFLAGS += ["-DWINDOWS_H"]

class CustomBuildExtension(build_ext):
    def run(self):
        self.build_lib = BUILD_DIR
        self.inplace = False
        self.parallel = int(os.cpu_count() * 1.5)
        super().run()
        
def wrap_c_lib():

    def get_deps(directory):
        try:
            deps = get_key(dotenv_path=f"{directory}/.env", key_to_get="DEPS").split()
            return [f"{OBJ_DIR}/{dep}" for dep in deps]
        except Exception:
            return []

    def get_extension(module):
        name = f'{LIB_NAME}.{module}'
        sources = [f'{WRAPPER_DIR}/{module}/__init__.py']
        objects = []
        if module not in ["enums", "gmp"]:
            objects += get_deps(f'{SRC_DIR}/{module}') + [
                f'{OBJ_DIR}/{module}/{f.replace(".c", ".o")}' for f \
                    in os.listdir(os.path.join(SRC_DIR, module)) \
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
            extra_compile_args=CFLAGS,
            extra_link_args=LDFLAGS
        )

    cython_directives = {
        "boundscheck": "False",
        "wraparound": "False",
        "cdivision": "True",
        "language_level": "3",
        "emit_code_comments": "False",
    }

    excludes = ["__pycache__"]
    modules = [item for item in os.listdir(WRAPPER_DIR) \
        if os.path.isdir(os.path.join(WRAPPER_DIR, item)) and item not in excludes]
    top_module = Extension(
        name="cryptocalcul",
        sources=[f"{WRAPPER_DIR}/cryptocalcul.py"]
        # + [f'{WRAPPER_DIR}/{module}/__init__.py' for module in modules],
    )
    extensions = [get_extension(module) for module in modules] 
    # + [parent_module]
    
    # Cython setup
    setup(
        name="wrappers",
        ext_modules=cythonize(
            extensions,
            compiler_directives=cython_directives,
            quiet=True,
            annotate=True,
        ) + [top_module],
        # packages=find_packages(SRC_DIR),
        # package_data={"*": ['*.pxd']},
        cmdclass={'build_ext': CustomBuildExtension},
        zip_safe=False,
    )

if __name__ == '__main__':
    freeze_support()
    set_start_method('spawn')
    p = Process(target=wrap_c_lib)
    p.start()