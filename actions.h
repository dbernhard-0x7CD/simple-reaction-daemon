
#ifndef SRD_ACTIONS_H
#define SRD_ACTIONS_H

#include "printing.h"

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

    // Pointer to struct or string with more info
    // about the given action
    void*       object;

    // Delay until this action is performed when run is DOWN
    int         delay;

    // When to run this action
    conn_state_t run;
} action_t;

/* 
* A command action which will be performed for one target
* if down for a specific duration.
*/
typedef struct action_cmd_t {
    const char* command;
    const char* user;
} action_cmd_t;

/*
* Action to log (append) a message to a file.
*/
typedef struct action_log_t {
    // Path to the file (folder must exist)
    const char* path;

    // Message to log. May contain placeholders: %ip, %sdt (start of downtime)
    const char* message;

    // Username of the owner from the logfile
    const char* username;
} action_log_t;

/*
* Restarts the given service. The service-name must have
* characters not in [a-Z] or [0-9] escaped to _HEX where
* HEX is the hex value of the character as string.
* ip is used when logging to indicate from which target
* this restart originated.
* Returns 1 on success, else 0.
*/
int restart_service(const logger_t* logger, const char* name, const char* ip);

/*
* Restarts the system (errors out if the executing user has
* insufficient permissions). 
* Returns 1 on success, and otherwise 0.
*/
int restart_system(const logger_t* logger);

/*
 * Runs the given command.
 * Returns 1 if success, else 0.
 */
int run_command(const logger_t *logger, const action_cmd_t* cmd);

/*
* Logs the given message to the given file by appending.
*/
int log_to_file(const logger_t* logger, const char* path, const char* message, const char* username);

#endif
