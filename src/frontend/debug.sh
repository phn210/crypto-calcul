# source .env
export $(grep -v '^#' src/frontend/.env | xargs)
# libasan=/opt/homebrew/Cellar/llvm/19.1.2/lib/clang/19/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
python=./.venv/bin/python3
dylib=$LIBASAN
# dylib=$LIBTSAN
# dylib=$LIBUSAN
DYLD_INSERT_LIBRARIES=$dylib $python src/frontend/test.py