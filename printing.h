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
    // for avoiding race conditions when writing
    pthread_mutex_t *stdout_mut;

    // the current loglevel
    enum loglevel *level;

    // prefix for each message
    char* prefix;
} logger_t;

/* Define some macros to print inside a mutex */
#define sprint(logger, ...)                          \
    const struct timespec timeout = { .tv_nsec = 0, .tv_sec = 1 }; \
    if (pthread_mutex_timedlock(logger->stdout_mut, &timeout) != 0) \
    {                                                \
        fprintf(stdout, "Unable to get lock: ");     \
        fprintf(stdout, "%s", logger->prefix);       \
        fprintf(stdout, __VA_ARGS__);                \
    }                                                \
    else                                             \
    {                                                \
        fprintf(stdout, "%s", logger->prefix);       \
        fprintf(stdout, __VA_ARGS__);                \
        pthread_mutex_unlock(logger->stdout_mut);    \
    }

#define sprint_raw(logger, ...)                             \
    if (pthread_mutex_lock(logger->stdout_mut) != 0)        \
    {                                                       \
        fprintf(stdout, "Unable to get lock: ");            \
    }                                                       \
    else                                                    \
    {                                                       \
        fprintf(stdout, __VA_ARGS__);                                \
        pthread_mutex_unlock(logger->stdout_mut);           \
    }

#define uprint(logger, ...)     \
    fprintf(stdout, logger->prefix);     \
    fprintf(stdout, __VA_ARGS__);

#define sprint_debug(logger, ...)              \
    if (*logger->level <= LOGLEVEL_DEBUG)      \
    {                                          \
        sprint(logger, "DEBUG: " __VA_ARGS__); \
    }

#define sprint_debug_raw(logger, ...)          \
    if (*logger->level <= LOGLEVEL_DEBUG)      \
    {                                          \
        sprint_raw(logger, __VA_ARGS__);       \
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

#define sprint_error(logger, ...)               \
    if (*logger->level <= LOGLEVEL_ERROR)       \
    {                                           \
        sprint(logger, "ERROR: " __VA_ARGS__);  \
    }

#define print_debug(logger, ...)          \
    if (*logger->level <= LOGLEVEL_DEBUG) \
    {                                     \
        uprint(logger, "DEBUG: " __VA_ARGS__);   \
    }

#define print_info(logger, ...)          \
    if (*logger->level <= LOGLEVEL_INFO) \
    {                                    \
        uprint(logger, __VA_ARGS__);            \
    }

#define print_quiet(logger, ...)          \
    if (*logger->level <= LOGLEVEL_QUIET) \
    {                                     \
        uprint(logger, __VA_ARGS__);             \
    }

#define print_error(logger, ...)          \
    if (*logger->level <= LOGLEVEL_ERROR) \
    {                                     \
        uprint(logger, "ERROR: " __VA_ARGS__);   \
    }


enum loglevel to_loglevel(const char* str_loglevel);

#endif
