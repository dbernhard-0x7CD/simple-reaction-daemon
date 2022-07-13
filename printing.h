#include <pthread.h>

#ifndef SRD_PRINTING_H
#define SRD_PRINTING_H

/* Define some macros to print inside a mutex */
#define print(mutex, ...)                     \
    if (pthread_mutex_lock(&mutex) != 0)      \
    {                                         \
        printf(__VA_ARGS__);                  \
    } else {                                  \
        printf(__VA_ARGS__);                  \
        pthread_mutex_unlock(&mutex);         \
    }
    

#define print_debug(mutex, ...)              \
    if (loglevel <= LOGLEVEL_DEBUG)   \
    {                                 \
        print(mutex, "DEBUG: " __VA_ARGS__); \
    }

#define print_info(mutex, ...)              \
    if (loglevel <= LOGLEVEL_INFO)   \
    {                                \
        print(mutex, "INFO: " __VA_ARGS__); \
    }

#endif
