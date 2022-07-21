
#include "printing.h"

#ifndef SRD_ACTIONS_H
#define SRD_ACTIONS_H

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
} action_log_t;

/*
* Restarts the given service. The service-name must have
* characters not in [a-Z] or [0-9] escaped to _HEX where
* HEX is the hex value of the character as string.
* ip is used when logging to indicate from which target
* this restart originated.
* Returns 1 on success, else 0.
*/
int restart_service(logger_t logger, const char* name, const char* ip);

/*
* Restarts the system (errors out if the executing user has
* insufficient permissions). 
* Returns 1 on success, and otherwise 0.
*/
int restart_system();

/*
 * Runs the given command.
 * Returns 1 if success, else 0.
 */
int run_command(logger_t logger, const action_cmd_t* cmd);

/*
* Logs the given message to the given file by appending.
*/
int log_to_file(logger_t logger, const char* path, const char* message);

#endif
