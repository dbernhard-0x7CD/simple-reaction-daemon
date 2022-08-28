#include <errno.h>
#include <fts.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libconfig.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>


// Our includes
#include "util.h"
#include "srd.h"
#include "printing.h"
#include "actions.h"

char *const configd_path = "/etc/srd/";
char *const config_main = "/srd.conf";
char *const version = "0.0.7-dev";

// application configuration
enum loglevel loglevel = LOGLEVEL_DEBUG;

/* used to exit the main loop and stop all threads */
int running = 1;

/* used to lock stdout as all threads write to it */
pthread_mutex_t stdout_mut;

// loaded at startup
char* default_gw;

// format used for datetimes
const char* datetime_format = "%Y-%m-%d %H:%M:%S";
int use_custom_datetime_format = 0;

// used for printing to stdout
logger_t* logger;

int main()
{
    // await stop signal, then we stop (set running = 0)
    signal(SIGALRM, signal_handler); 

    logger_t log;
    log.level = &loglevel;
    log.stdout_mut = &stdout_mut;
    logger = &log;

    print_error(logger, "Starting srd (Simple Reaction Daemon) version %s\n", version);

    // create a mutex; if unsuccessful we stop
    if (pthread_mutex_init(&stdout_mut, NULL) != 0)
    {
        print_error(logger, "Unable to initialize mutex\n");
        return EXIT_FAILURE;
    }

    // try to get default gateway
    default_gw = get_default_gw();

    if (default_gw == NULL) {
        print_error(logger, "Unable to get default gateway\n");

        /*
        * We only exit if not in DEBUG mode.
        */
#ifndef DEBUG
        pthread_mutex_destroy(&stdout_mut);
        return EXIT_FAILURE;
#else
        default_gw = "127.0.0.1";
#endif
    }

    // load configuration files for connectivity targets
    int success = 0;
    int connectivity_targets;
    connectivity_check_t **connectivity_checks = load(configd_path, &success, &connectivity_targets);
    if (!success || connectivity_checks == NULL)
    {
        // print only debug, as load is responsible for printing the error
        print_debug(logger, "Unable to load configuration.\n");
        return EXIT_FAILURE;
    }
#if DEBUG
    printf("Printing all connectivity targets:\n");
    for (int i = 0; i < connectivity_targets; i++) {
        connectivity_check_t cc = *connectivity_checks[i];

        printf("Connectivity target %d has ip %s\n", i, cc.ip);
        printf("\t depends on: %s\n", cc.depend_ip);
        printf("\t period: %d\n", cc.period);
        printf("\tnum actions: %d\n", cc.actions_count);
    }
#endif

    print_debug(logger, "default gateway %s\n", default_gw);
    
    fflush(stdout);

    pthread_t threads[connectivity_targets];
    check_arguments_t args[connectivity_targets];

    // Start threads for each connectivity target
    // for each target in `connectivity_checks` we create one thread
    for (int i = 0; i < connectivity_targets; i++)
    {
        args[i] = (check_arguments_t) { connectivity_checks, i, connectivity_targets };
        pthread_create(&threads[i], NULL, (void *)run_check, (void *)&args[i]);
    }
    print_error(logger, "Started all target checks (%d).\n", connectivity_targets);

    // used to await only specific signals
    sigset_t waitset;
    siginfo_t info;

    if (running)
    {
        sigemptyset(&waitset);

        sigaddset(&waitset, SIGALRM);
        sigaddset(&waitset, SIGTERM);
        sigaddset(&waitset, SIGABRT);
        sigaddset(&waitset, SIGKILL);
        sigaddset(&waitset, SIGSTOP);

        sigprocmask(SIG_BLOCK, &waitset, NULL);

        print_info(logger, "Awaiting shutdown signal\n");

        // waits until a signal arrives
        int result;
        
        while ((result = sigwaitinfo(&waitset, &info) < 0)) {
            print_debug(logger, "sigwaitinfo received error %d\n", errno);
        }
        running = 0;

        print_debug(logger, "Got signal %d\n", info.si_signo);
    }

    print_error(logger, "Shutting down Simple Reaction Daemon\n");
    fflush(stdout);

    // kill and join all threads
    for (int i = 0; i < connectivity_targets; i++)
    {
        pthread_kill(threads[i], SIGALRM);
    }
    for (int i = 0; i < connectivity_targets; i++)
    {
        pthread_join(threads[i], NULL);
    }

    print_debug(logger, "Killed all threads\n");

    // free all memory
    for (int i = 0; i < connectivity_targets; i++) {
        connectivity_check_t* ptr = connectivity_checks[i];

        free((char *)ptr->ip);
        free((char *)ptr->depend_ip);

        close(ptr->epoll_fd);
        close(ptr->socket);

        // free cmd if it is a command (contains the command) or service-restart (contains service name)
        for (int i = 0; i < ptr->actions_count; i++) {
            if (strcmp(ptr->actions[i].name, "command") == 0) {
                action_cmd_t* cmd = (action_cmd_t*) ptr->actions[i].object;
                free ((char *)cmd->command);
                free ((char *)cmd->user);
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "reboot") == 0) {
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "service-restart") == 0) {
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "log") == 0) {
                action_log_t* action_log = (action_log_t*) ptr->actions[i].object;

                free((char *)action_log->message);
                free((char *)action_log->path);
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "influx") == 0) {
                action_influx_t* influx = (action_influx_t*) ptr->actions[i].object;

                free((char *)influx->host);
                free((char *)influx->authorization);
                free((char *)influx->endpoint);
                free((char *)influx->line_data);
                free(ptr->actions[i].object);
            }
            free((char *)ptr->actions[i].name);
        }
        free(ptr->actions);
        free(ptr);
    }
    free(connectivity_checks);
    free(default_gw);

    if (use_custom_datetime_format) {
        free((char *) datetime_format);
    }

    pthread_mutex_destroy(&stdout_mut);

    print_error(logger, "Finished Simple Reaction Daemon.\n");
    fflush(stdout);

    return EXIT_SUCCESS;
} // main end

connectivity_check_t* get_dependency(connectivity_check_t **ccs, const int n, char const *ip) {

    for (int i = 0; i < n; i++) {
        connectivity_check_t* ptr = ccs[i];

        if (strcmp(ip, ptr->ip) == 0) {
            return ptr;
        }
    }

    return NULL;
}

int is_available(connectivity_check_t *check, int strict) {
    // status could be STATE_UP or STATE_UP_NEW
    if (check->status & STATE_UP) {
        return 1;
    }
    if (check->status == STATE_NONE && strict == 0) {
        return 1;
    }

    sprint_debug(logger, "Not available: %s (status: %d)\n", check->ip, check->status);
    return 0;
}

void run_check(check_arguments_t *args)
{
    const int idx = args->idx;
    connectivity_check_t* check = args->connectivity_checks[idx];

    pthread_setname_np(pthread_self(), check->ip);

    // store time to calculate the time of the next ping
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    const struct timespec period = { .tv_nsec = 0, .tv_sec = check->period };

    struct timespec next_period = timespec_add(now, period);

    connectivity_check_t* dependency = NULL;
    
    if (check->depend_ip != NULL) {
        dependency = get_dependency(args->connectivity_checks, args->amount_targets, check->depend_ip);

        if (dependency == NULL) {
            sprint_error(logger, "[%s]: Unable to find check: %s\n", check->ip, check->depend_ip);
            running = 0;
            kill(getpid(), SIGALRM);
            return;
        }
    }

    // main loop: check connectivity repeatedly
    while (running)
    {
        // check if our dependency is available
        if (check->depend_ip != NULL) {
            sprint_debug(logger, "[%s]: Checking for dependency %s\n",check->ip, check->depend_ip);

            int available = is_available(dependency, 1);

            if (available == 0) {
                sprint_info(logger, "[%s]: Awaiting dependency %s\n", check->ip, check->depend_ip);

                next_period = timespec_add(next_period, period);
                sleep(check->period);
                
                continue;
            }
        }
        int connected = check_connectivity(check);
    
        char current_time[32];
        get_current_time(current_time, 32, datetime_format, NULL);

        // downtime in seconds
        double downtime_s;
        double uptime_s = -1.0;

        // previous downtime; set when up-new
        double prev_downtime = 0.0;
        
        if (connected == 1)
        {
            if ((check->status & STATE_UP) == 0) {
                sprint_info(logger, "[%s]: Reachable %s\n", check->ip,  current_time);
                if (check->status & STATE_DOWN) {
                    prev_downtime = calculate_difference(check->timestamp_last_reply, now);
                }
                check->timestamp_first_reply = now;

                check->status = STATE_UP_NEW;
            } else {
                check->status = STATE_UP;
            }

            check->timestamp_last_reply = now;
            downtime_s = 0;

            uptime_s = calculate_difference(check->timestamp_first_reply, now);
        }
        else if (connected == 0)
        {   
            if (check->status & STATE_DOWN) {
                check->status = STATE_DOWN;
            } else {
                check->status = STATE_DOWN_NEW;

                check->timestamp_first_failed = now;

                uptime_s = calculate_difference(check->timestamp_first_reply, check->timestamp_last_reply);
            }

            downtime_s = calculate_difference(check->timestamp_first_failed, now);

            sprint_info(logger, "[%s]: %s: Ping FAILED. Now for %0.3fs\n", check->ip, current_time, downtime_s);
        } else if (!running) {
            break; 
        } else {
            sprint_error(logger, "[%s]: %s: Error when checking connectivity. (connected: %d)\n", check->ip, current_time, connected);

            check->status = STATE_NONE;

            clock_gettime(CLOCK_REALTIME, &now);

            int32_t wait_time = calculate_difference_ms(now, next_period);
            next_period = timespec_add(now, period);

            usleep(wait_time * 1000);
            continue;
        }
        fflush(stdout);
        // print_debug(logger, "[%s]: determined state: %d\n", check->ip , check->status);

        // check if any action is required
        for (int i = 0; running && i < check->actions_count; i++)
        {
            action_t this_action = check->actions[i];
            
            // print_debug(logger, "[%s]: action: %s this_action.run %d\n", check->ip, this_action.name, this_action.run);

            unsigned int state_match = check->status & this_action.run;
            int superior = (state_match >= this_action.run || this_action.run == STATE_ALL);

            int state_up_new_diff = (this_action.run != STATE_UP_NEW || check->actions[i].delay <= prev_downtime);

            int state_down_diff = (this_action.run != STATE_DOWN || check->actions[i].delay <= downtime_s);

            // printf("\tstate_match: %d", state_match);
            // printf("\tsuperior: %d", superior);
            // printf("\tstate_up_new: %d ", state_up_new_diff);
            // printf("\tstate_down_diff: %d\n ", state_down_diff);

            int should_run = state_match && superior &&
                                    state_up_new_diff &&
                                    state_down_diff;
            if (should_run)
            {
                sprint_info(logger, "[%s]: Performing action: %s\n", check->ip, check->actions[i].name);

                if (strcmp(this_action.name, "service-restart") == 0)
                {
                    restart_service(logger, this_action.object, check->ip);
                }
                else if (strcmp(this_action.name, "reboot") == 0)
                {
                    sprint_info(logger, "[%s]: Sending restart signal\n", check->ip);
                    int res = restart_system(logger);

                    if (res == 0) { // unable to restart
                        sprint_error(logger, "Unable to restart using dbus. Will try command\n");

                        const char* cmd = "reboot";
                        action_cmd_t cmd_reboot;
                        cmd_reboot.command = cmd;

                        run_command(logger, &cmd_reboot, 5e3);
                    } else {
                        sprint_info(logger, "[%s]: Reboot scheduled. \n", check->ip);
                    }
                }
                else if (strcmp(this_action.name, "command") == 0)
                {
                    action_cmd_t *cmd = this_action.object;

                    // we use a copy as the command has placeholders
                    action_cmd_t copy = *cmd;

                    double downtime;
                    if (check->status == STATE_UP_NEW) {
                        downtime = prev_downtime;
                    } else {
                        downtime = downtime_s; // we are still down (or up)
                    }

                    copy.command = insert_placeholders(cmd->command, check, datetime_format, downtime, uptime_s, connected);
                    
                    sprint_debug(logger, "\tCommand: %s\n", copy.command);
                    fflush(stdout);

                    run_command(logger, &copy, copy.timeout * 1e3);

                    free((char*)copy.command);
                } else if (strcmp(this_action.name, "log") == 0) { 
                    action_log_t* action_log = (action_log_t*) this_action.object;

                    double downtime;
                    if (check->status == STATE_UP_NEW) {
                        downtime = prev_downtime;
                    } else {
                        downtime = downtime_s; // we are still down (or up)
                    }

                    const char* message = insert_placeholders(action_log->message, check, datetime_format, downtime, uptime_s, connected);

                    int r = log_to_file(logger, action_log->path, message, action_log->username);
                    if (r == 0) {
                        sprint_error(logger, "[%s]: Unable to log to file %s\n", check->ip ,action_log->path);
                    }
                    
                    free((char *)message);
                } else if (strcmp(this_action.name, "influx") == 0) {
                    action_influx_t* action = this_action.object;

                    action_influx_t copy = *action;

                    copy.line_data = insert_placeholders(action->line_data, check, datetime_format, downtime_s, uptime_s, connected);

                    influx(logger, copy);

                    free((void *)copy.line_data);

                    // because the copy may have established a new connection
                    action->conn_socket = copy.conn_socket;
                }
                else
                {
                    sprint_error(logger, "[%s]: This action is NOT implemented: %s\n", check->ip, this_action.name);
                } 
            }
        } // end for loop. (to check if any action has to be taken)

        fflush(stdout);

        if (running) {
            // calculate time until next check should be performed
            clock_gettime(CLOCK_REALTIME, &now);

            int32_t wait_time = calculate_difference_ms(now, next_period);

            if (wait_time < 0) {
                char str_time[32];
                get_current_time(str_time, 32, datetime_format, NULL);

                print_error(logger, "[%s]: Behind in schedule by %d ms at %s. Check your period and your timeouts of the actions.\n", check->ip, wait_time, str_time);

                next_period = timespec_add(now, period);

                continue;
            }

            next_period = timespec_add(next_period, period);

            usleep(wait_time * 1000);
        }
    } // end check while(running)

    sprint_debug(logger, "[%s]: Shutting this target check down.\n", check->ip);
}

void signal_handler(int s)
{
    // stop if we receive one of those signals
    if (s == SIGTERM || s == SIGABRT || s == SIGKILL || s == SIGSTOP || s == SIGALRM)
    {
        running = 0;
        return;
    }
    printf("Unhandled signal %d\n", s);
    fflush(stdout);
}

int check_connectivity(connectivity_check_t* cc)
{
    int success = 0;

    int i;
    for (i = 0; i < cc->num_pings; i++) {
#if DEBUG
        cc->socket = create_socket(logger);
        cc->epoll_fd = create_epoll(cc->socket);
#endif
        int ping_success = ping(logger, &cc->socket, &cc->epoll_fd, cc->ip, &cc->latency, cc->timeout);

#if DEBUG
        close(cc->socket);
        close(cc->epoll_fd);
#endif

        if (ping_success == 1) {
            success = 1;
            break;
        } else if (ping_success < 0) {
            return (-1);
        }
    }
    if (i == cc->num_pings && success == 0) {
        return 0;
    }

    sprint_debug(logger, "[%s]: Ping has success: %d with latency: %2.3fms\n", cc->ip, success, cc->latency * 1000);

    return success;
}

connectivity_check_t **load(char *directory, int *success, int *count)
{
    FTS *fts_ptr;
    FTSENT *p, *children_ptr;
    int opt = FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR;

    int cur_size = 0;
    int cur_max = 8;
    connectivity_check_t **conns = malloc(cur_max * sizeof(connectivity_check_t *));

    char *args[2];
    args[0] = directory;
    args[1] = NULL;

    if ((fts_ptr = fts_open(args, opt, NULL)) == NULL)
    {
        print_error(logger, "Unable to read directory %s\n", directory);
        *success = 0;
        return NULL;
    }

    children_ptr = fts_children(fts_ptr, 0);
    if (children_ptr == NULL)
    {
        print_error(logger, "No config files at %s\n", configd_path);
        fflush(stdout);
        *success = 0;
        return NULL;
    }

    while ((p = fts_read(fts_ptr)) != NULL)
    {
        if (p->fts_info == FTS_F)
        {
            // only accept if the path ends with '.conf'
            if (!ends_with(p->fts_path, ".conf")) {
                continue;
            }

            print_info(logger, "Read config file %s\n", p->fts_path);

            if (!load_config(p->fts_path, &conns, &cur_size, &cur_max))
            {
                print_error(logger, "Unable to load config %s\n", p->fts_path);
                *success = 0;
                return NULL;
            }
        }
    }

    // if no configuration files were found
    if (cur_size == 0)
    {
        print_error(logger, "Missing config file at %s\n", configd_path);
        print_error(logger, "Configuration files must end with .conf\n");
        fflush(stdout);
        *success = 0;

        fts_close(fts_ptr);
        return NULL;
    }
    fts_close(fts_ptr);

    *success = 1;
    *count = cur_size;

    return conns;
}

int load_config(char *cfg_path, connectivity_check_t*** conns, int* conns_size, int* max_conns_size)
{
    config_t cfg;

    config_init(&cfg);

    if (!config_read_file(&cfg, cfg_path))
    {
        print_error(logger, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        
        return 0;
    }

    config_setting_t *setting;
    const char* ip_field;

    if (!config_lookup_string(&cfg, "destination", &ip_field))
    {
        print_error(logger, "%s is missing setting: destination\n", cfg_path);
        config_destroy(&cfg);
        return 0;
    }

    // iterate over all IPs in the destination string
    const char* cur_char = ip_field;
    const char* end = ip_field + strlen(ip_field);
    const char* cur_ip_start = ip_field;

    while (cur_char <= end) {
        if (*(cur_char) == '\0' || *cur_char == ',') {

            connectivity_check_t* cc = (connectivity_check_t* )malloc(sizeof(connectivity_check_t));

            // initial values for a target
            cc->socket = -1;
            cc->epoll_fd = -1;

            struct timespec time_zero;
            time_zero.tv_nsec = 0;
            time_zero.tv_sec = 0;

            cc->timestamp_first_failed = time_zero;
            cc->timestamp_first_reply = time_zero;
            cc->timestamp_last_reply = time_zero;

            int length = cur_char - cur_ip_start;

            // one more allocated, for null delimiter
            char* ip = malloc((length + 1) * sizeof(char));

            memcpy(ip, cur_ip_start, length);
            *(ip + length) = '\0';

            cc->ip = str_replace(ip, "%gw", default_gw);
            free(ip);

            // initial connectivity_check values
            cc->status = STATE_NONE;

            if (!config_lookup_int(&cfg, "period", &cc->period))
            {
                print_error(logger, "%s is missing setting: period\n", cfg_path);
                config_destroy(&cfg);
                return 0;
            }

            // timeout (can be an integer or double)
            int timeout;
            if (config_lookup_int(&cfg, "timeout", &timeout)) {
                cc->timeout = (double)timeout;
            } else if (!config_lookup_float(&cfg, "timeout", &cc->timeout))
            {
                print_error(logger, "%s is missing setting: timeout\n", cfg_path);
                config_destroy(&cfg);
                return 0;
            }
            if (cc->timeout < 0) {
                print_error(logger, "%s timeout cannot be negative\n", cfg_path);
                config_destroy(&cfg);
                return 0;
            }

            // depends configuration
            const char* depend_ip;
            if (!config_lookup_string(&cfg, "depends", &depend_ip)) {
                cc->depend_ip = NULL;
            } else {
                char* replaced = str_replace(depend_ip, "%gw", default_gw);

                cc->depend_ip = replaced;
            }

            // num_pings configuration
            int num_pings = 1;
            config_lookup_int(&cfg, "num_pings", &num_pings);
            cc->num_pings = num_pings;

            // check if this is "srd.conf" (config_main)
            if (ends_with(cfg_path, config_main)) {

#ifndef DEBUG
                const char *setting_loglevel;
                // loglevel of srd
                if (config_lookup_string(&cfg, "loglevel", &setting_loglevel))
                {
                    int new_loglevel = to_loglevel(setting_loglevel);
                    
                    if (new_loglevel == INVALID_LOGLEVEL)
                    {
                        print_error(logger, "%s contains unknown loglevel: %s\n", cfg_path, setting_loglevel);
                        return 0;
                    }
                    loglevel = new_loglevel;
                } else {
                    print_error(logger, "No loglevel defined in %s.\n", cfg_path);
                }
#endif
                // datetime_format
                const char* format;
                if (config_lookup_string(&cfg, "datetime_format", &format)) {
                    datetime_format = strdup(format);
                    use_custom_datetime_format = 1;
                }
            } // end if for "srd.conf"

            // load the actions
            setting = config_lookup(&cfg, "actions");
            if (setting == NULL)
            {
                print_error(logger, "%s: missing actions in config file.\n", cfg_path);
                config_destroy(&cfg);
                return 1;
            }
            cc->actions_count = config_setting_length(setting);
            cc->actions = calloc(cc->actions_count, sizeof(action_t));

            // Iterate over all actions
            for (int i = 0; i < cc->actions_count; i++)
            {
                const config_setting_t *action = config_setting_get_elem(setting, i);
                action_t* this_action = &cc->actions[i];

                // action name configuration
                const char *action_name;
                if (!config_setting_lookup_string(action, "action", &action_name))
                {
                    print_error(logger, "%s: element is missing the action\n", cfg_path);
                    config_destroy(&cfg);
                    return 0;
                }
                int action_len = strlen(action_name) + 1;
                cc->actions[i].name = (char *)malloc(action_len * sizeof(char));
                strcpy((char *)cc->actions[i].name, action_name);

                // run_if configuration
                const char *run_if_str;
                if (!config_setting_lookup_string(action, "run_if", &run_if_str))
                {
                    // default run_if setting is RUN_DOWN
                    this_action->run = STATE_DOWN;
                } else {
                    if (strcmp(run_if_str, "down") == 0) {
                        this_action->run = STATE_DOWN;
                    } else if (strcmp(run_if_str, "up") == 0) {
                        this_action->run = STATE_UP;
                    } else if (strcmp(run_if_str, "always") == 0) {
                        this_action->run = STATE_ALL;
                    } else if (strcmp(run_if_str, "up-new") == 0) {
                        this_action->run = STATE_UP_NEW;
                    } else if (strcmp(run_if_str, "down-new") == 0) {
                        this_action->run = STATE_DOWN_NEW;
                    } else {
                        print_error(logger, "%s: Action %s is has unknown run_if: %s\n", cfg_path, action_name, run_if_str);
                        config_destroy(&cfg);
                        return 0;
                    }
                }
                
                // delay configuration
                if (!config_setting_lookup_int(action, "delay", &this_action->delay))
                {
                    this_action->delay = 0;
                }

                // Load the properties for action_name
                if (strcmp(action_name, "reboot") == 0)
                {
                    // nothing to do
                }
                else if (strcmp(action_name, "service-restart") == 0)
                {
                    if (!config_setting_lookup_string(action, "name", (const char **)&cc->actions[i].object))
                    {
                        print_error(logger, "%s: element is missing the name\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }

                    char *escaped_servicename = escape_servicename((char *)cc->actions[i].object);
                    
                    cc->actions[i].object = escaped_servicename;
                }
                else if (strcmp(action_name, "command") == 0)
                {
                    action_cmd_t *cmd = malloc(sizeof(action_cmd_t));

                    const char* command;
                    if (!config_setting_lookup_string(action, "cmd", &command))
                    {
                        print_error(logger, "%s: element is missing the cmd\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    command = str_replace(command, "%ip", (char *)cc->ip);

                    cmd->command = command;

                    // load username
                    const char* username;
                    if (!config_setting_lookup_string(action, "user", &username))
                    {
                        cmd->user = NULL;
                    } else {
                        int username_len = strlen(username) + 1;
                        cmd->user = (char *) malloc(username_len * sizeof(char));
                        strcpy((char *)cmd->user, username);
                    }

                    // load timeout
                    int32_t timeout_s;
                    if (!config_setting_lookup_int(action, "timeout", &timeout_s)) {
                        cmd->timeout = 60*60*24; // 1 day
                    } else {
                        cmd->timeout = timeout_s;
                    }

                    this_action->object = cmd;
                }
                else if (strcmp(action_name, "log") == 0) {
                    action_log_t *action_log = malloc(sizeof(action_log_t));

                    const char* path;
                    if (!config_setting_lookup_string(action, "path", &path))
                    {
                        print_error(logger, "%s: element is missing the path\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    } else {
                        path = strdup(path);

                        action_log->path = str_replace(path, "%ip", cc->ip);

                        free((char*)path);
                    }

                    const char* message;
                    if (!config_setting_lookup_string(action, "message", &message))
                    {
                        print_error(logger, "%s: element is missing the message\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    } else {
                        action_log->message = str_replace(message, "%ip", (char *)cc->ip);
                    }

                    const char* username;
                    if (!config_setting_lookup_string(action, "user", &username))
                    {
                        action_log->username = NULL;
                    } else {
                        action_log->username = strdup(username);
                    }

                    this_action->object = action_log;
                }
                else if (strcmp(action_name, "influx") == 0) {
                    action_influx_t *action_influx = malloc(sizeof(action_influx_t));
                    action_influx->conn_socket = -1;

                    // load the host
                    const char* host;
                    if (!config_setting_lookup_string(action, "host", &host))
                    {
                        print_error(logger, "%s: element is missing the host\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->host = strdup(host);

                    // load the port
                    if (!config_setting_lookup_int(action, "port", &action_influx->port))
                    {
                        action_influx->port = 8086;
                    }

                    // load the endpoint
                    const char* endpoint;
                    if (!config_setting_lookup_string(action, "endpoint", &endpoint))
                    {
                        print_error(logger, "%s: element is missing the endpoint\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->endpoint = strdup(endpoint);

                    // load authorization
                    const char* authorization;
                    if (!config_setting_lookup_string(action, "authorization", &authorization))
                    {
                        print_error(logger, "%s: element is missing the authorization\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->authorization = strdup(authorization);

                    // load linedata format
                    const char* linedata;
                    if (!config_setting_lookup_string(action, "linedata", &linedata))
                    {
                        print_error(logger, "%s: element is missing the linedata\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->line_data = str_replace(linedata, "%ip", cc->ip);

                    this_action->object = action_influx;
                }
                else
                {
                    print_error(logger, "%s: unknown element in configuration on line %d\n", cfg_path, action->line);
                    config_destroy(&cfg);
                    return 0;
                }
            }

            // update the connectivity check in the array and increase size
            (*conns)[*conns_size] = cc;
            (*conns_size)++;

            // check if we need more space in conns
            if (*conns_size >= *max_conns_size) {
                // increase size of conns
                *max_conns_size += 1;
                *conns = realloc(*conns, (*max_conns_size) * sizeof(connectivity_check_t *));

                if (conns == NULL) {
                    print_error(logger, "Out of memory\n");

                    return 0;
                }
            }

            cur_ip_start = cur_char + 1;
        }
        cur_char++;
    }

    config_destroy(&cfg);

    return 1;
}
