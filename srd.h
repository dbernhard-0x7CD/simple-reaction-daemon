#ifndef SRD_H
#define SRD_H

#include "actions.h"
#include <time.h>


/* A connectivity check is one target to which we do connectivity checks.
 * Each config file represents one such check. As Each target can have its
 * own IP, timeout, period and actions.
 */
typedef struct connectivity_check_t
{
    // config name where this target is defined
    char* name;

    // target IP address
    const char *address;

    // IP address this check depends on
    const char *depend_ip;

    // Timeout in seconds
    double timeout;

    // Period in which this IP is pinged in seconds
    int period;

    // number of times to retry sending a ping
    int num_pings;

    // Latency of the last ping in seconds; -1.0 if not successful
    double latency;

    // Status of last ping
    conn_state_t status;

    // Timestamp of the last successfull ping
    struct timespec timestamp_last_reply;

    // Timestamp of the first successfull ping. Set when we switch from any state to STATE_UP_NEW
    struct timespec timestamp_first_reply;

    // Timestamp of the first failing ping, set when we switch from STATE_UP to STATE_DOWN_NEW
    struct timespec timestamp_first_failed;

    // Last time we sent a ping
    struct timespec timestamp_latest_try;

    // Count of actions if this target is not reachable
    int actions_count;

    // Actions to perform (dependend on the status)
    action_t *actions;

    // Socket used to ping the target
    int socket;

    // On epoll filedescriptor for receiving from socket
    int epoll_fd;

    // buffer for sending packets
    char* snd_buffer;

    // buffer for receiving packets
    char* rcv_buffer;
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

    /* Logger which should be used by this thread. */
    logger_t logger;
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
 * Returns a pointer to some check with the given IP.
 * NULL is returned if no check is found with the given IP.
 */
connectivity_check_t* get_dependency(connectivity_check_t **ccs, const int n, char const *ip);

/*
 * Checks if the given check is available. Returns 1 if it is, else 0.
 */
int is_available(connectivity_check_t *check, int strict);

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
int check_connectivity(const logger_t* logger, connectivity_check_t *check);

/* Loads the configuration file at the given path and appends
 * all found connectivity targets to conns.
 * conns_size is a pointer to the current size of the conns array
 * max_conns_size is the current maximum for conns
 * Returns 1 on success, else 0.
 */
int load_config(const char *cfg_path, connectivity_check_t ***conns, int *conns_size, int *max_conns_size);

/*
 * Handle signals like SIGTERM to stop this program.
 */
void signal_handler(int);

#define PACKETSIZE 64

#endif
