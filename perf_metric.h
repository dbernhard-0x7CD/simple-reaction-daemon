
#ifndef SRD_PERF_METRIC_H
#define SRD_PERF_METRIC_H

#include <time.h>

#include "util.h"

#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)

#define MEASUREMENT_PREFIX measure_
#define DIFF_PREFIX diff_

/* Definitions which stay even when no DEBUG is set */

/*
 * Creates a new metric called 'name'
 */
#define MEASURE_INIT(name)                          \
    struct timespec CONCAT(MEASUREMENT_PREFIX, name);

/*
 * Starts the clock for the metric 'name'
 */
#define MEASURE_START(name)                         \
    clock_gettime(CLOCK, &CONCAT(MEASUREMENT_PREFIX, name));

/*
 * Writes the duration in the format "[%d days] %H:%M:%S.%3N" into str_ptr
 */
#define MEASURE_GET_SINCE_STR(name, str_ptr)                    \
    int CONCAT(DIFF_PREFIX, name);                              \
    CONCAT(DIFF_PREFIX, name) =                                 \
        measure_get_since_ms(&CONCAT(MEASUREMENT_PREFIX, name));\
    ms_to_string(CONCAT(DIFF_PREFIX, name), str_ptr);           \

/*
 * Returns the duration as double (in seconds).
 */
#define MEASURE_GET_SINCE(name)                                \
    measure_get_since(&CONCAT(MEASUREMENT_PREFIX, name));

#if DEBUG
/*
 * Creates a new metric called 'name'
 */
#define MEASURE_INIT_DEBUG(name)            \
    struct timespec name;

/*
 * Starts the clock for the metric 'name'
 */
#define DEBUG_START_DEBUG(name)              \
    clock_gettime(CLOCK, &name);
     
/*
 * Writes the duration in the format "[%d days] %H:%M:%S.%3N" into str_ptr
 */
#define GET_SINCE_STR_DEBUG(name, str_ptr)                      \
    struct timespec CONCAT(DIFF_PREFIX, name);                  \
    CONCAT(DIFF_PREFIX, name) =                                 \
        measure_get_since_ms(&CONCAT(MEASUREMENT_PREFIX, name));\
    ms_to_string(CONCAT(DIFF_PREFIX, name), str_ptr);           \

/*
 * Returns the duration as double (in seconds).
 */
#define MEASURE_GET_SINCE_DEBUG(name, str_ptr)                \
    measure_get_since(&CONCAT(MEASUREMENT_PREFIX, name));

#else // we're not in DEBUG, thus ignore those macros

#define MEASURE_INIT_DEBUG(name) /* removed */
#define DEBUG_START_DEBUG(name) /* removed */
#define GET_SINCE_DEBUG(name, str_ptr) /* removed */
#define MEASURE_GET_SINCE_STR_DEBUG(name, str_ptr) /* removed */
#define MEASURE_GET_SINCE_DEBUG(name, str_ptr) /* removed */

#endif

// Normal definitions

/*
 * Returns the seconds (as double) since start_time
 */
static inline double measure_get_since(struct timespec* start_time) {
    struct timespec now;
    clock_gettime(CLOCK, &now);

    return calculate_difference(*start_time, now);
}

static inline int32_t measure_get_since_ms(struct timespec* start_time) {
    struct timespec now;
    clock_gettime(CLOCK, &now);

    return calculate_difference_ms(*start_time, now);
}

#endif
