#include "file_io.h"

// Reads a whole file into a newly allocated buffer
cc_status_t read_file(const char *path, unsigned char **data, size_t *len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL)
        return CC_ERR_IO;

    cc_status_t status = CC_ERR_IO;
    long size;
    if (fseek(file, 0, SEEK_END) == 0 && (size = ftell(file)) >= 0 && fseek(file, 0, SEEK_SET) == 0)
    {
        *len = (size_t)size;
        *data = malloc(*len + 1);
        if (*data == NULL)
            status = CC_ERR_NOMEM;
        else if (fread(*data, 1, *len, file) != *len)
            free(*data);
        else
            status = CC_OK;
    }

    fclose(file);
    return status;
}

cc_status_t write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *file = fopen(path, "wb");
    if (file == NULL)
        return CC_ERR_IO;
    size_t written = fwrite(data, 1, len, file);
    int closed = fclose(file);
    return written == len && closed == 0 ? CC_OK : CC_ERR_IO;
}
