from Cython.Build import cythonize
from Cython.Distutils import build_ext
from dotenv import load_dotenv, get_key
from multiprocessing import Process, freeze_support, set_start_method
from setuptools import setup, Extension
import platform, logging

logging.getLogger("dotenv").setLevel(logging.ERROR)
load_dotenv()

SRC_DIR = platform.os.environ["C_SRC_DIR"]
OBJ_DIR = platform.os.environ["ROOT_OBJ_DIR"]
BUILD_DIR = platform.os.environ["ROOT_BIN_DIR"]
WRAPPER_DIR = f"{SRC_DIR}/wrappers"
LIB_NAME = WRAPPER_DIR.split("/")[-1]

CFLAGS = platform.os.environ["CFLAGS"].split(" ")
LDFLAGS = platform.os.environ["LDFLAGS"].split(" ")

if platform.os.environ["APP_ENV"] == "debug":
    platform.os.environ["CC"] = "clang"
    SANITIZER = platform.os.environ["SANITIZER"]
    CFLAGS += platform.os.environ["SAN_CFLAGS"].replace("$(SANITIZER)", SANITIZER).split(" ")
    LDFLAGS += platform.os.environ["SAN_LDFLAGS"].replace("$(SANITIZER)", SANITIZER).split(" ")

if (platform.system() == 'Windows'):
    CFLAGS += ["-DWINDOWS_H"]

def wrap_c_lib():
    class CustomBuildExtension(build_ext):
        def run(self):
            self.build_lib = BUILD_DIR
            self.inplace = False
            self.parallel = int(platform.os.cpu_count() * 1.5)
            super().run()
            
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
                    in platform.os.listdir(platform.os.path.join(SRC_DIR, module)) \
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
    modules = [item for item in platform.os.listdir(WRAPPER_DIR) \
        if platform.os.path.isdir(platform.os.path.join(WRAPPER_DIR, item)) and item not in excludes]
    extensions = [get_extension(module) for module in modules]
    
    # Cython setup
    setup(
        name="wrappers",
        ext_modules=cythonize(
            extensions,
            compiler_directives=cython_directives,
            quiet=True,
            annotate=True,
        ),
        cmdclass={'build_ext': CustomBuildExtension},
        zip_safe=False,
    )

if __name__ == '__main__':
    freeze_support()
    set_start_method('spawn')
    p = Process(target=wrap_c_lib)
    p.start()