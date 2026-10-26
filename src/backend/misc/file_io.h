#ifndef FILE_IO_H
#define FILE_IO_H

#include "common.h"

// Reads a whole file into *data (allocated, must be freed); *data is untouched on failure
CC_NODISCARD cc_status_t read_file(const char *path, unsigned char **data, size_t *len);
CC_NODISCARD cc_status_t write_file(const char *path, const unsigned char *data, size_t len);

#endif
