#ifndef SRD_H
#define SRD_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>
struct timespec;

#include "actions.h"
#include "printing.h"

#define CLOCK CLOCK_REALTIME_COARSE


/*
 * These flags are used in connectivity_check_t
 */
#define FLAG_AWAITING_DEPENDENCY 0b1
#define FLAG_STARTED 0b10
#define FLAG_STARTING_DEPENDENCY 0b100
#define FLAG_IS_HOSTNAME 0b1000

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

    // target IP
    struct sockaddr_storage* sockaddr;

    // IP address this check depends on
    const char *depend_ip;

    // Timeout in seconds
    float timeout;

    // Period in which this IP is pinged in seconds
    uint8_t period;

    // number of times to retry sending a ping
    uint8_t num_pings;

    // Latency of the last ping in seconds; -1.0 if not successful
    float latency;

    // previous downtime. set when up-new is triggered
    uint32_t previous_downtime;

    // Status of last ping
    conn_state_t state;

    // Timestamp of the last successfull ping
    struct timespec timestamp_last_reply;

    // Timestamp of the first successfull ping.
    // Set when state switches from any state to STATE_UP.
    struct timespec timestamp_first_reply;

    // Timestamp of the first failing ping, set when we switch from STATE_UP to STATE_DOWN_NEW
    struct timespec timestamp_first_failed;

    // Last time we sent a ping. This is used to check if tests are stalled
    struct timespec timestamp_latest_try;

    // Count of actions if this target is not reachable
    uint8_t actions_count;

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

    // loglevel for this target 
    enum loglevel loglevel;

    // Flags for this target
    uint16_t flags;
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
 * Defines if the daemon is still running.
 * Any positive value means we're running and zero means we're stopping.
 */
extern int running;

/*
 * Pointer to the datetime format this application uses.
*/
extern const placeholder_t* datetime_ph;

/*
 * Entry point into this service. Loads all configs and starts a thread for each
 * of them.
 */
int main();

/*
 * Tries to start the given check. Returns -1 if there is an error.
 */
int start_check(pthread_t* threads, check_arguments_t* args, connectivity_check_t** ccs, const uint16_t n, const uint16_t idx);

/*
 * Periodically checks this target.
 */
void run_check(check_arguments_t *);

/*
 * Returns a pointer to some check with the given IP.
 * NULL is returned if no check is found with the given IP.
 * Also sets idx to the index of the check with the given IP.
 */
connectivity_check_t* get_dependency(connectivity_check_t **ccs, const uint16_t n, char const *ip, uint16_t* idx);

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
 * Checks if we are still able to ping the target.
 * Returns 1 if the target is still reachable, else 0.
 * 
 * If the target is not reachable and it was in state STATE_UP 
 * first_failed will be set.
 * If we cannot determine connectivity a negative value
 * is returned.
 */
int check_connectivity(const logger_t* logger, connectivity_check_t *target, struct timespec* first_failed);

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
