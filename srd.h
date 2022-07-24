#include "actions.h"
#include <time.h>

#ifndef SRD_H
#define SRD_H

/*
 * Connectivity status for a target (connectivity_check_t).
 */
enum conn_status
{
    STATUS_SUCCESS,
    STATUS_FAILED,
    STATUS_NONE
};

/* A connectivity check is one target to which we do connectivity checks.
 * Each config file represents one such check. As Each target can have its
 * own IP, timeout, period and actions.
 */
typedef struct connectivity_check_t
{
    // target IP address
    const char *ip;

    // IP address this check depends on
    const char *depend_ip;

    // Timeout in seconds
    double timeout;

    // Period in which this IP is pinged
    int period;

    int num_pings;

    // Latency of the last ping; -1 if not successful
    double latency;

    // Status of last ping
    enum conn_status status;

    // Timestamp of the last successfull ping
    struct timespec timestamp_last_reply;

    // Count of actions if this target is not reachable
    int actions_count;

    // Actions if the target is not reachable
    action_t *actions;
} connectivity_check_t;

/*
 * Type of the arguments passed to each thread running for one
 * connectivity check.
 */
typedef struct check_arguments_t
{
    /* All connectivity checks */
    connectivity_check_t **connectivity_checks;

    /* Index of the check this thread is responsible for */
    int idx;

    /* Sum of all checks */
    int amount_targets;
} check_arguments_t;

/*
 * Entry point into this service. Loads all configs and starts a thread for each
 * of them.
 */
int main();

/*
 * Periodically checks this target.
 */
void run_check(check_arguments_t *);

/*
 * Checks if the given ip is available. Returns 1 if it is, else 0.
 * If a dependency does not exist a negative value is returned.
 */
int is_available(connectivity_check_t **ccs, const int n, char const *ip, int strict);

/*
 * Loads all connectivity checks inside the directory.
 * These files have to be '.conf' files and follow the
 * srd.conf syntax.
 */
connectivity_check_t **load(char *const directory, int *success, int *count);

/*
 * Checks if this machine is still able to ping the target.
 * Returns 1 if the IP is still reachable in the given timeout,
 * else 0. If we cannot determine connectivity a negative value
 * is returned.
 */
int check_connectivity(connectivity_check_t *check);

/* Loads the configuration file at the given path and appends
 * all found connectivity targets to conns.
 * conns_size is a pointer to the current size of the conns array
 * max_conns_size is the current maximum for conns
 * Returns 1 on success, else 0.
 */
int load_config(char *cfg_path, connectivity_check_t ***conns, int *conns_size, int *max_conns_size);

/*
 * Handle signals like SIGTERM to stop this program.
 */
void signal_handler(int);

#endif
