#include "printing.h"
#include "string.h"

enum loglevel to_loglevel(const char* str_loglevel) {
    if (strcmp("INFO", str_loglevel) == 0)
    {
        return LOGLEVEL_INFO;
    }
    else if (strcmp("DEBUG", str_loglevel) == 0)
    {
        return LOGLEVEL_DEBUG;
    }
    else if (strcmp("QUIET", str_loglevel) == 0)
    {
        return LOGLEVEL_QUIET;
    }
    else if (strcmp("ERROR", str_loglevel) == 0)
    {
        return LOGLEVEL_ERROR;
    }
    else
    {
        return INVALID_LOGLEVEL;
    }
}
