export $(grep -v '^#' src/frontend/.env | xargs)
python=./.venv/bin/python3
dylib=$LIBASAN
# dylib=$LIBTSAN
# dylib=$LIBUSAN
DYLD_INSERT_LIBRARIES=$dylib $python src/frontend/test.py