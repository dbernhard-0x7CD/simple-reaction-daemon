#ifndef SRD_PRINTING_H
#define SRD_PRINTING_H

#include <pthread.h>

/*
 * Log level of each target.
 */
enum loglevel
{
    LOGLEVEL_DEBUG, // Everything
    LOGLEVEL_INFO,  // When a ping fails, when an action is performed
    LOGLEVEL_QUIET, // reserved for later
    LOGLEVEL_ERROR,  // Nothing connection related, only when started and when stopped
    INVALID_LOGLEVEL, // This should never happen
};

typedef struct logger_t
{
    pthread_mutex_t *stdout_mut;
    enum loglevel *level;
} logger_t;

/* Define some macros to print inside a mutex */
#define sprint(logger, ...)                          \
    if (pthread_mutex_lock(logger->stdout_mut) != 0) \
    {                                                \
        printf("Unable to get lock: " __VA_ARGS__);  \
    }                                                \
    else                                             \
    {                                                \
        printf(__VA_ARGS__);                         \
        pthread_mutex_unlock(logger->stdout_mut);    \
    }

#define sprint_debug(logger, ...)              \
    if (*logger->level <= LOGLEVEL_DEBUG)      \
    {                                          \
        sprint(logger, "DEBUG: " __VA_ARGS__); \
    }

#define sprint_debug_raw(logger, ...)              \
    if (*logger->level <= LOGLEVEL_DEBUG)      \
    {                                          \
        sprint(logger, __VA_ARGS__); \
    }

#define sprint_info(logger, ...)         \
    if (*logger->level <= LOGLEVEL_INFO) \
    {                                    \
        sprint(logger, __VA_ARGS__);     \
    }

#define sprint_quiet(logger, ...)         \
    if (*logger->level <= LOGLEVEL_QUIET) \
    {                                     \
        sprint(logger, __VA_ARGS__);      \
    }

#define sprint_error(logger, ...)         \
    if (*logger->level <= LOGLEVEL_ERROR) \
    {                                     \
        sprint(logger, __VA_ARGS__);      \
    }

#define print_debug(logger, ...)          \
    if (*logger->level <= LOGLEVEL_DEBUG) \
    {                                     \
        printf("DEBUG: " __VA_ARGS__);    \
    }

#define print_info(logger, ...)          \
    if (*logger->level <= LOGLEVEL_INFO) \
    {                                    \
        printf(__VA_ARGS__);             \
    }

#define print_quiet(logger, ...)          \
    if (*logger->level <= LOGLEVEL_QUIET) \
    {                                     \
        printf(__VA_ARGS__);              \
    }

#define print_error(logger, ...)          \
    if (*logger->level <= LOGLEVEL_ERROR) \
    {                                     \
        printf(__VA_ARGS__);              \
    }


int to_loglevel(const char* str_loglevel);

#endif
