#include "common.h"

const char *cc_strerror(cc_status_t status)
{
    switch (status)
    {
    case CC_OK:
        return "Success";
    case CC_ERR_INVALID_ARG:
        return "Invalid argument";
    case CC_ERR_UNSUPPORTED:
        return "Operation not supported";
    case CC_ERR_NOMEM:
        return "Memory allocation failed";
    case CC_ERR_IO:
        return "File input/output error";
    case CC_ERR_RNG:
        return "Random source unavailable";
    case CC_ERR_INVALID_INPUT:
        return "Invalid input data";
    case CC_ERR_MSG_TOO_LONG:
        return "Message too long";
    case CC_ERR_DECRYPT:
        return "Decryption failed";
    case CC_ERR_VERIFY:
        return "Verification failed";
    case CC_ERR_BUFFER_TOO_SMALL:
        return "Output buffer too small";
    case CC_ERR_NO_KEY:
        return "No key available";
    }
    return "Unknown error";
}
