
#include "printing.h"

#ifndef SRD_ACTIONS_H
#define SRD_ACTIONS_H

/*
* When to run the given action.
*/
enum run_if { RUN_UP, RUN_ALWAYS, RUN_DOWN, RUN_UP_AGAIN };

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
    enum run_if run;
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
int log_to_file(const logger_t* logger, const char* path, const char* message);

#endif
