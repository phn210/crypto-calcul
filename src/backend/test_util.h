#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "common.h"

// Prints FAILED (detected by CTest) when a call does not return the expected status
#define EXPECT_STATUS(expr, expected)                                                    \
    do                                                                                   \
    {                                                                                    \
        cc_status_t expect_st_ = (expr);                                                 \
        if (expect_st_ != (expected))                                                    \
            printf("%s:\tFAILED (got \"%s\")\n", #expr, cc_strerror(expect_st_));        \
    } while (0)

#define EXPECT_OK(expr) EXPECT_STATUS(expr, CC_OK)

#endif
