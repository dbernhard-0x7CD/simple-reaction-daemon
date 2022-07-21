#include <pthread.h>

#ifndef SRD_PRINTING_H
#define SRD_PRINTING_H

/*
 * Log level of each target.
 */
enum loglevel
{
    LOGLEVEL_DEBUG,
    LOGLEVEL_INFO
};

typedef struct logger_t
{
    pthread_mutex_t *stdout_mut;
    enum loglevel *level;
} logger_t;

/* Define some macros to print inside a mutex */
#define print(logger, ...)                          \
    if (pthread_mutex_lock(logger.stdout_mut) != 0) \
    {                                               \
        printf(__VA_ARGS__);                        \
    }                                               \
    else                                            \
    {                                               \
        printf(__VA_ARGS__);                        \
        pthread_mutex_unlock(logger.stdout_mut);   \
    }

#define print_debug(logger, ...)              \
    if (*logger.level <= LOGLEVEL_DEBUG)          \
    {                                        \
        print(logger, "DEBUG: " __VA_ARGS__); \
    }

#define print_info(logger, ...)              \
    if (*logger.level <= LOGLEVEL_INFO)          \
    {                                       \
        print(logger, "INFO: " __VA_ARGS__); \
    }

#endif
