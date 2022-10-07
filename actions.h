
#ifndef SRD_ACTIONS_H
#define SRD_ACTIONS_H

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "printing.h"

typedef uint32_t replacement_info_t;

#define FLAG_RAN_UP_NEW 0b1
#define FLAG_RAN_DOWN_NEW 0b10

typedef struct placeholder_t {
    const char* raw_message;

    replacement_info_t info;
} placeholder_t;

#define CLOSE(action_influx)                    \
    close(action_influx->conn_socket);          \
    close(action_influx->conn_epoll_write_fd);  \
    close(action_influx->conn_epoll_read_fd);   \
    action_influx->conn_socket = -1;            \
    action_influx->conn_epoll_write_fd = -1;    \
    action_influx->conn_epoll_read_fd = -1;     \
/*
 * Connectivity status for a target (connectivity_check_t).
 */
typedef enum conn_state_t
{
    STATE_UP        = 0b0001,
    STATE_DOWN      = 0b0010,
    STATE_UP_NEW    = 0b0101,
    STATE_DOWN_NEW  = 0b1010,
    STATE_NONE      = 0b0000,
    STATE_ALL       = 0b1111,
} conn_state_t;

/* 
* An action which will be performed for one target
* if down for delay seconds.
*/
typedef struct action_t {
    // Defines which action to perform
    const char* name;

    /* Pointer to struct or string with more info
     * about the given action.
     * Currently:
     *      * action_cmd_t
     *      * action_log_t
     *      * action_influx_t
     *      * to char* which is the service name if name is "restart-service"
     */
    void*       object;

    // Delay until this action is performed when run is DOWN
    uint32_t    delay;

    // When to run this action
    conn_state_t run_state;

    // Flags for this
    uint16_t flags;
} action_t;

/* 
* A command action which will be performed for one target
* if down for a specific duration.
*/
typedef struct action_cmd_t {
    /* 
     * Placeholder for the command to be executed.
     */
    struct placeholder_t cmd_ph;

    /*
     * User under which this command is executed.
     */
    const char* user;
    uint32_t timeout;
} action_cmd_t;

/*
* Action to log (append) a message to a file.
*/
typedef struct action_log_t {
    // Path to the file (folder must exist)
    const char* path;

    /* File handle */
    FILE* file;

    // Message to log. May contain placeholders: %ip, %sdt (start of downtime)
    struct placeholder_t message_ph;

    // Username of the owner from the logfile
    const char* username;

    // Header for the log-file. Only written when creating the file
    const char* header;
} action_log_t;

/*
 * Action to insert data into an influxDB instance.
 */
typedef struct action_influx_t {
    // host
    const char* host;

    struct sockaddr_storage* sockaddr;

    int port;

    // path for the endpoint, may include bucket and organization
    const char* endpoint;

    // authorization token
    const char* authorization;

    /* placeholder_t for one line which is sent.
     * raw_message could be something like: 
     *          latency,host=%ip value=%lat_ms %timestamp
     */
    struct placeholder_t line;

    // socket to send the data
    int conn_socket;

    // epoll fd to send the data
    int conn_epoll_write_fd;

    // epoll fd to receive an answer
    int conn_epoll_read_fd;

    // timeout for the insertion of one line
    int timeout;

    /* Used to store some properties of this action.
     * FLAG_IS_HOSTNAME indicates that host is not an IP
     * address and needs to be resolved.
     */
    int flags;
} action_influx_t;

/*
* Restarts the given service. The service-name must have
* characters not in [a-Z] or [0-9] escaped to _HEX where
* HEX is the hex value of the character as string.
* Returns 1 on success, else 0.
*/
int restart_service(const logger_t* logger, const char* name);

/*
* Restarts the system (errors out if the executing user has
* insufficient permissions). 
* Returns 1 on success, and otherwise 0.
*/
int restart_system(const logger_t* logger);

/*
 * Runs the given command. If it does not exit within timeout_ms milliseconds
 * it'll be killed.
 * Returns 1 if success, else 0.
 */
int run_command(const logger_t *logger, const action_cmd_t* cmd, const uint32_t timeout_ms, const char* actual_command);

/*
* Logs the given message to the given file by appending.
*/
int log_to_file(const logger_t* logger, action_log_t* action_log, const char* actual_line);

/*
 * Executes the given influx action. Returns 1 on success, else 0.
 */
int influx(const logger_t* logger, action_influx_t* action, const char* actual_line);

#endif
