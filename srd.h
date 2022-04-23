
#ifndef SRD_H
#define SRD_H

/* 
* An action which will be performed for one target
* if down for delay seconds.
*/
typedef struct action_t {
    const char* name;
    void*       object;
    int         delay;
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
* Log level of each target.
*/
enum loglevel { LOGLEVEL_DEBUG, LOGLEVEL_INFO };

/*
* Connectivity status for a target.
*/
enum conn_status { STATUS_SUCCESS, STATUS_FAILED, STATUS_NONE };

/* A connectivity check is one target to which we do connectivity checks.
* Each config file represents one such check. As Each target can have its
* own IP, timeout, period and actions.
*/
typedef struct connectivity_check_t {
    int count;
    const char *ip;
    int timeout;
    int period;
    enum conn_status status;
    struct timespec timestamp_last_reply;
    action_t* actions;
} connectivity_check_t;

/*
* Entry point into this service. Loads all configs and starts a thread for each
* of them.
*/
int main();

/*
* Periodically checks this target. 
*/
void run_check(connectivity_check_t*);

/*
* Restarts the given service. The service-name must have
* characters not in [a-Z] or [0-9] escaped to _HEX where
* HEX is the hex value of the character as string.
* ip is used when logging to indicate from which target
* this restart originated.
* Returns 1 on success, else 0.
*/
int restart_service(const char* name, const char* ip);

/*
* Restarts the system (errors out if the executing user has
* insufficient permissions). 
* Returns 1 on success, and otherwise 0.
*/
int restart_system(const char* ip);

/*
* Loads all connectivity checks inside the directory.
* These files have to be '.conf' files and follow the
* srd.conf syntax.
*/
connectivity_check_t** load(char *const directory, int* success, int* count);

/*
 * Runs the given command.
 * Returns 1 if success, else 0.
 */
int run_command(const action_cmd_t* cmd);

/*
 * Checks if this machine is still able to ping the given IP.
 * Returns 1 if the IP is still reachable in the given timeout,
 * else 0. If we cannot determine connectivity a negative value
 * is returned
 */
int check_connectivity(const char* ip, int timeout);

/* Loads the configuration file at the given path in 
* ip, period, timeout, count of actions and global loglevel.
* Returns 1 on success, else 0.
*/
int load_config(char *cfg_path, const char **ip, int *freq, int *timeout, int* count, action_t **actions);

/*
* Handle signals like SIGTERM to stop this program.
*/
void signal_handler(int);

/*
 * Accepts a service name and returns the same service name escaped.
 * Each character not in [a-Z] or [0-9] will get escaped to '_HEX' where HEX is
 * the HEX value of the value
 */
char* escape_servicename(char*);

/*
* Checks if the string 'str' ends with 'end'
*/
int ends_with(char* str, char* end);

#endif
