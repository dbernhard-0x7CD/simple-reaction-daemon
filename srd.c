#include <errno.h>
#include <fts.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libconfig.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <pthread.h>


// Our includes
#include "util.h"
#include "srd.h"
#include "printing.h"
#include "actions.h"

char *const configd_path = "/etc/srd/";
char *const config_main = "/srd.conf";
char *const version = "0.0.8-dev";

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
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);

    logger_t log;
    log.level = &loglevel;
    log.stdout_mut = &stdout_mut;
    log.prefix = "[main]: ";
    logger = &log;

    print_info(logger, "Starting srd (Simple Reaction Daemon) version %s\n", version);

    // create a mutex; if unsuccessful we stop
    if (pthread_mutex_init(&stdout_mut, NULL) != 0)
    {
        print_error(logger, "Unable to initialize mutex\n");
        return EXIT_FAILURE;
    }

    /* Try to get default gateway
    * Use localhost as gateway when debugging and no gateway is available.
    */
    while ((default_gw = get_default_gw()) == NULL) {
#ifdef DEBUG
        char* debug_gw = "127.0.0.1";
        default_gw = malloc((1 + strlen(debug_gw)) * sizeof(char));
        memcpy(default_gw, debug_gw, 1 + strlen(debug_gw));
        break;
#else
        print_error(logger, "Unable to get default gateway. Retrying in 60 seconds... \n");

        sleep(60);

        if (!running) {
            return EXIT_SUCCESS;
        }
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

        printf("Connectivity target %d has ip %s\n", i, cc.address);
        printf("\t depends on: %s\n", cc.depend_ip);
        printf("\t period: %d\n", cc.period);
        printf("\tnum actions: %d\n", cc.actions_count);
    }
#endif

    print_debug(logger, "default gateway %s\n", default_gw);

    pthread_t threads[connectivity_targets];
    check_arguments_t args[connectivity_targets];

    // Start threads for each connectivity target
    // for each target in `connectivity_checks` we create one thread
    int i;
    for (i = 0; i < connectivity_targets; i++)
    {
        int s = start_check(threads, args, connectivity_checks, connectivity_targets, i);
        if (s < 0) {
            running = 0;
            sprint_error(logger, "Unable to start\n");
            break;
        }
    }

    if (i == connectivity_targets) {
        print_info(logger, "Started all target checks (%d).\n", connectivity_targets);
    }

    // used to await only specific signals
    sigset_t waitset;
    siginfo_t info;

    if (running)
    {
        sigemptyset(&waitset);

        sigaddset(&waitset, SIGINT);
        sigaddset(&waitset, SIGALRM);
        sigaddset(&waitset, SIGTERM); // sent by systemd
        sigaddset(&waitset, SIGABRT);
        sigaddset(&waitset, SIGKILL);
        sigaddset(&waitset, SIGSTOP);

        sigprocmask(SIG_BLOCK, &waitset, NULL);

        print_info(logger, "Awaiting shutdown signal\n");

        // waits until a signal arrives
        int result;

        const struct timespec timeout = { .tv_nsec = 0, .tv_sec = 60 };

        struct timespec now;
        
        while ((result = sigtimedwait(&waitset, &info, &timeout)) < 0) {
            if (!running) {
                goto shutdown;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                clock_gettime(CLOCK_REALTIME, &now);

                for (int i = 0; i < connectivity_targets; i++)
                {
                    const connectivity_check_t* check = connectivity_checks[i];

                    double diff = calculate_difference(check->timestamp_latest_try, now);

                    // + 1 to not report some small overhead occured
                    if (check->period + 1 < diff && ((check->flags & FLAG_AWAITING_DEPENDENCY) == 0)) {

                        char str_now[32];
                        get_current_time(str_now, 32, datetime_format, NULL);

                        sprint_error(logger, "%s: thread for %s is stalled. Period is %d but last check was %1.2f seconds ago \n", str_now, args[i].logger.prefix, check->period, diff);
                    }
                }
                sprint_debug(logger, "Checking threads...\n");
                continue;
            }
            sprint_debug(logger, "Received another signal: %s\n", strerror(errno));
        }

        running = 0;

        sprint_debug(logger, "Got signal %d\n", info.si_signo);
    }

shutdown:
    sprint_info(logger, "Shutting down Simple Reaction Daemon\n");
    fflush(stdout);

    // kill and join all threads
    for (int i = 0; i < connectivity_targets; i++)
    {
        if (connectivity_checks[i]->flags & FLAG_STARTED) {
            pthread_kill(threads[i], SIGALRM);
        }
    }
    for (int i = 0; i < connectivity_targets; i++)
    {
        if (connectivity_checks[i]->flags & FLAG_STARTED) {
            pthread_join(threads[i], NULL);
        }
    }

    sprint_debug(logger, "Killed all threads\n");

    // free all memory
    for (int i = 0; i < connectivity_targets; i++) {
        // args
        if (connectivity_checks[i]->flags & FLAG_STARTED) {
            check_arguments_t cur_args = args[i];
            free(cur_args.logger.prefix);
        }

        // connectivity_checks
        connectivity_check_t* ptr = connectivity_checks[i];

        free((char *)ptr->address);
        free((char *)ptr->depend_ip);
        free((char *)ptr->name);
        free((char *)ptr->snd_buffer);
        free((char *)ptr->rcv_buffer);

        if (ptr->epoll_fd > 0) {
            close(ptr->epoll_fd);
        }
        if (ptr->socket > 0) {
            close(ptr->socket);
        }

        // free cmd if it is a command (contains the command) or service-restart (contains service name)
        for (int i = 0; i < ptr->actions_count; i++) {
            if (strcmp(ptr->actions[i].name, "command") == 0) {
                action_cmd_t* cmd = (action_cmd_t*) ptr->actions[i].object;
                free ((char *)cmd->cmd_ph.raw_message);
                free ((char *)cmd->user);
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "reboot") == 0) {
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "service-restart") == 0) {
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "log") == 0) {
                action_log_t* action_log = (action_log_t*) ptr->actions[i].object;

                free((char *)action_log->message_ph.raw_message);
                free((char *)action_log->path);
                if (action_log->username) {
                    free((char *)action_log->username);
                }
                if (action_log->header) {
                    free((char *)action_log->header);
                }
                free(ptr->actions[i].object);
            } else if (strcmp(ptr->actions[i].name, "influx") == 0) {
                action_influx_t* influx = (action_influx_t*) ptr->actions[i].object;

                free((char *)influx->host);
                free(influx->sockaddr);
                free((char *)influx->authorization);
                free((char *)influx->endpoint);
                free((char *)influx->line.raw_message);
                if (influx->conn_epoll_read_fd > 0) {
                    close(influx->conn_epoll_read_fd);
                }
                if (influx->conn_epoll_write_fd > 0) {
                    close(influx->conn_epoll_write_fd);
                }
                if (influx->conn_socket > 0) {
                    close(influx->conn_socket);
                }
                free(ptr->actions[i].object);
            }
            free((char *)ptr->actions[i].name);
        }
        free(ptr->actions);
        free(ptr->sockaddr);
        free(ptr);
    }
    free(connectivity_checks);
    free(default_gw);

    if (use_custom_datetime_format) {
        free((char *) datetime_format);
    }

    pthread_mutex_destroy(&stdout_mut);

    print_info(logger, "Finished Simple Reaction Daemon.\n");
    fflush(stdout);

    return EXIT_SUCCESS;
} // main end

connectivity_check_t* get_dependency(connectivity_check_t **ccs, const uint16_t n, char const *ip, uint16_t* idx) {

    for (int i = 0; i < n; i++) {
        connectivity_check_t* ptr = ccs[i];

        if (strcmp(ip, ptr->address) == 0) {
            if (idx != NULL) {
                *idx = i;
            }
            return ptr;
        }
    }

    return NULL;
}

int start_check(pthread_t* threads, check_arguments_t* args, connectivity_check_t** ccs, const uint16_t n, const uint16_t idx) {
    connectivity_check_t* check = ccs[idx];
    // return success if already started
    if (check->flags & FLAG_STARTED) {
        return 1;
    }

    // if we're already starting a dependency then we're in a loop
    // thus, return error
    if (check->flags & FLAG_STARTING_DEPENDENCY) {
        print_error(logger, "There is a dependency loop in one of your configs with %s.\n", check->address);

        return -1;
    }

    // check if it has a dependency
    if (check->depend_ip != NULL) {
        uint16_t dep_idx = -1;
        check->flags |= FLAG_STARTING_DEPENDENCY;

        if (get_dependency(ccs, n, check->depend_ip, &dep_idx) == NULL) {
            sprint_error(logger, "Unable to find dependency: %s\n", check->depend_ip);
            return -1;
        }

        if (start_check(threads, args, ccs, n, dep_idx) < 0) {
            return -1;
        }
        // now the dependency is running
    }

    // If this check has no own loglevel, take that from srd.conf
    if (check->loglevel == INVALID_LOGLEVEL) {
        check->loglevel = loglevel;
    }
    /*
     * Create a logger with the prefix CONFIG_NAME-TARGET_IP
     */
    logger_t thread_logger = *logger;
    thread_logger.level = &check->loglevel;

    size_t confname_length = strlen(check->name);
    size_t hostname_length = strlen(check->address);

    char* prefix = malloc((6 + confname_length + hostname_length) * sizeof(char));
    prefix[0] = '[';
    strncpy(prefix + 1, check->name, confname_length);
    prefix[1 + confname_length] = '-';
    strncpy(prefix + 2 + confname_length, check->address, hostname_length);
    memcpy(prefix + 2 + confname_length + hostname_length, "]: ", 3 * sizeof(char));

    prefix[5 + confname_length + hostname_length] = '\0';
    thread_logger.prefix = prefix;
 
    args[idx] = (check_arguments_t) { ccs, idx, n, thread_logger };

    print_debug(logger, "Starting thread for %s.\n", check->address);
    check->flags |= FLAG_STARTED;
    pthread_create(&threads[idx], NULL, (void *)run_check, (void *)&args[idx]);
    
    return 1;
}

int is_available(connectivity_check_t *check, int strict) {
    // status could be STATE_UP or STATE_UP_NEW
    if (check->state & STATE_UP) {
        return 1;
    }
    if (check->state == STATE_NONE && strict == 0) {
        return 1;
    }

    return 0;
}

void run_check(check_arguments_t *args)
{
    const int idx = args->idx;
    connectivity_check_t* check = args->connectivity_checks[idx];

    check->flags |= FLAG_STARTED;

    pthread_setname_np(pthread_self(), check->address);

    logger_t* logger = &args->logger;

    // store time to calculate the time of the next ping
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    const struct timespec period = { .tv_nsec = 0, .tv_sec = check->period };

    struct timespec next_period = timespec_add(now, period);

    connectivity_check_t* dependency = NULL;
    
    if (check->depend_ip != NULL) {
        dependency = get_dependency(args->connectivity_checks, args->amount_targets, check->depend_ip, NULL);

        if (dependency == NULL) {
            sprint_error(logger, "Unable to find check: %s\n",  check->depend_ip);
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
            sprint_debug(logger, "Checking for dependency %s\n",check->depend_ip);

            int available = is_available(dependency, 1);

            if (available == 0) {
                sprint_info(logger, "Awaiting dependency %s\n", check->depend_ip);

                check->flags |= FLAG_AWAITING_DEPENDENCY;

                next_period = timespec_add(next_period, period);
                sleep(check->period);
                
                continue;
            }

            // Remove flag FLAG_AWAITING_DEPENDENCY
            check->flags &= ~FLAG_AWAITING_DEPENDENCY;
        }
        clock_gettime(CLOCK_REALTIME, &now);

        // Set latest try. Used to calculate if a target check is stalled
        check->timestamp_latest_try = now;
        
        int connected = check_connectivity(logger, check);
        if (!running) {
            break;
        }
        
        char current_time[32];
        get_current_time(current_time, 32, datetime_format, NULL);
        clock_gettime(CLOCK_REALTIME, &now);

        // downtime in seconds
        double downtime_s = -1.0;
        double uptime_s = -1.0;

        if (connected == 1)
        {
            sprint_info(logger, "Reachable %s\n", current_time);
            
            // set timestamp if the current statue is not STATE_UP
            if ((check->state & STATE_UP) == 0) {
                check->timestamp_first_reply = now;
            }

            // if we're not up (do not set state to STATE_UP_NEW if previous state was STATE_NONE)
            if ((check->state & STATE_UP) == 0 && check->state != STATE_NONE) {
                check->previous_downtime = calculate_difference(check->timestamp_last_reply, now);
                check->state = STATE_UP_NEW;
            } else {
                check->state = STATE_UP;
            }

            check->timestamp_last_reply = now;
            downtime_s = 0;

            uptime_s = calculate_difference(check->timestamp_first_reply, now);
        }
        else if (connected == 0)
        {
            if ((check->state & STATE_DOWN) == 0) {
                check->timestamp_first_failed = now;

                uptime_s = calculate_difference(check->timestamp_first_reply, check->timestamp_last_reply);
            }
            // if we're not down
            if ((check->state & STATE_DOWN) == 0 && check->state != STATE_NONE) {
                check->state = STATE_DOWN_NEW;
            } else {
                check->state = STATE_DOWN;
            }

            downtime_s = calculate_difference(check->timestamp_first_failed, now);

            sprint_info(logger, "%s: Ping FAILED. Now for %0.3fs\n", current_time, downtime_s);
        } else if (!running) {
            break; 
        } else {
            sprint_error(logger, "%s: Error when checking connectivity. (connected: %d)\n", current_time, connected);

            check->state = STATE_NONE;

            clock_gettime(CLOCK_REALTIME, &now);

            int32_t wait_time = calculate_difference_ms(now, next_period);
            next_period = timespec_add(now, period);

            usleep(wait_time * 1000);
            continue;
        }

        // check if any action is required
        for (int i = 0; running && i < check->actions_count; i++)
        {
            action_t this_action = check->actions[i];
            
            // print_debug(logger, "action: %s this_action.run %d\n", check->ip, this_action.name, this_action.run);

            unsigned int state_match = check->state & this_action.run;
            int superior = (state_match >= this_action.run || this_action.run == STATE_ALL);

            int state_up_new_diff = (this_action.run != STATE_UP_NEW || check->actions[i].delay <= check->previous_downtime);

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
                sprint_info(logger, "Performing action: %s\n", check->actions[i].name);

                if (strcmp(this_action.name, "service-restart") == 0)
                {
                    restart_service(logger, this_action.object);
                }
                else if (strcmp(this_action.name, "reboot") == 0)
                {
                    sprint_info(logger, "Sending restart signal\n");
                    int res = restart_system(logger);

                    if (res == 0) { // unable to restart
                        sprint_error(logger, "Unable to restart using dbus. Will try command\n");

                        placeholder_t placeholder = {.raw_message = "reboot", .info = 0};
                        
                        const char* cmd = "reboot";
                        action_cmd_t cmd_reboot = {.cmd_ph = placeholder};

                        run_command(logger, &cmd_reboot, 5e3, cmd);
                    } else {
                        sprint_info(logger, "Reboot scheduled. \n");
                    }
                }
                else if (strcmp(this_action.name, "command") == 0)
                {
                    action_cmd_t *cmd = this_action.object;

                    double downtime;

                    // if we are newly up; set downtime to previous downtime
                    if (check->state == STATE_UP_NEW) {
                        downtime = check->previous_downtime;
                    } else {
                        downtime = downtime_s; // we are still down (or up)
                    }

                    const char* actual_command = insert_placeholders(cmd->cmd_ph, check, datetime_format, downtime, uptime_s, connected);
                    
                    sprint_debug(logger, "\tCommand: %s\n", actual_command);

                    run_command(logger, cmd, cmd->timeout * 1e3, actual_command);

                    free((char*)actual_command);
                } else if (strcmp(this_action.name, "log") == 0) { 
                    action_log_t* action_log = (action_log_t*) this_action.object;

                    double downtime;
                    // set previous_downtime as downtime when we're newly up
                    if (check->state == STATE_UP_NEW) {
                        downtime = check->previous_downtime;
                    } else {
                        downtime = downtime_s; // we are still down (or up)
                    }

                    const char* message = insert_placeholders(action_log->message_ph, check, datetime_format, downtime, uptime_s, connected);

                    int r = log_to_file(logger, action_log, message);
                    if (r == 0) {
                        sprint_error(logger, "Unable to log to file %s\n", action_log->path);
                    }
                    
                    free((char *)message);
                } else if (strcmp(this_action.name, "influx") == 0) {
                    action_influx_t* action = this_action.object;

                    char* actual_line_data = insert_placeholders(action->line, check, datetime_format, downtime_s, uptime_s, connected);

                    influx(logger, action, actual_line_data);

                    free(actual_line_data);
                }
                else
                {
                    sprint_error(logger, "This action is NOT implemented: %s\n", this_action.name);
                } 
            }
        } // end for loop. (to check if any action has to be taken)

        if (running) {
            fflush(stdout);

            // calculate time until next check should be performed
            clock_gettime(CLOCK_REALTIME, &now);

            int32_t wait_time = calculate_difference_ms(now, next_period);

            if (wait_time < 0) {
                char str_time[32];
                get_current_time(str_time, 32, datetime_format, NULL);

                sprint_error(logger, "Behind in schedule by %d ms at %s. Check your period and your timeouts of the actions.\n", wait_time, str_time);

                next_period = timespec_add(now, period);

                continue;
            }

            next_period = timespec_add(next_period, period);

            usleep(wait_time * 1000);
        }
    } // end check while(running)

    print_debug(logger, "Shutting this target check down.\n");
}

void signal_handler(int s)
{
    // stop if we receive one of those signals
    if (s == SIGALRM || s == SIGINT || s == SIGKILL || s == SIGSTOP || s == SIGTERM || s == SIGABRT)
    {
        running = 0;
        print_debug(logger, "Received %d\n", s);
        signal(SIGPIPE, SIG_DFL);
        return;
    }
    char str_now[32];

    get_current_time(str_now, 32, datetime_format, NULL);

    print_error(logger, "Unhandled signal %d at %s\n", s, str_now);
    fflush(stdout);
}

int check_connectivity(const logger_t* logger, connectivity_check_t* cc)
{
    int success = 0;

    int i;
    for (i = 0; i < cc->num_pings; i++) {
        int ping_success = ping(logger, cc);

        if (ping_success == 1) {
            success = 1;
            break;
        } else if (ping_success < 0) {
            return (-1);
        } else if (!running) {
            return (-1);
        }
    }
    if (i == cc->num_pings && success == 0) {
        return 0;
    }

    sprint_debug(logger, "Ping has success: %d with latency: %2.3fms\n", success, cc->latency * 1000);

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
        *success = 0;

        fts_close(fts_ptr);
        return NULL;
    }
    fts_close(fts_ptr);

    *success = 1;
    *count = cur_size;

    return conns;
}

int load_config(const char *cfg_path, connectivity_check_t*** conns, int* conns_size, int* max_conns_size)
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

            connectivity_check_t* cc = (connectivity_check_t* )calloc(1, sizeof(connectivity_check_t));

            // initial values for a target
            cc->socket = -1;
            cc->epoll_fd = -1;

            // set the configuration name
            char* path = strdup(cfg_path);
            char* base = basename(path);
            cc->name = malloc((strlen(base) + 1) * sizeof(char));
            strcpy(cc->name, base);
            free((char *)path);

            // allocate buffers
            cc->snd_buffer = malloc(PACKETSIZE * sizeof(char));
            cc->rcv_buffer = malloc(PACKETSIZE * sizeof(char));

            // initialize timestamps which store first success; last (latest) reply, ...
            const struct timespec time_zero = { .tv_nsec = 0, .tv_sec = 0};

            cc->timestamp_first_failed = time_zero;
            cc->timestamp_first_reply = time_zero;
            cc->timestamp_last_reply = time_zero;

            // set no flags
            cc->flags = 0;

            // load ip
            int length = cur_char - cur_ip_start;

            // one more allocated, for null delimiter
            char* ip = malloc((length + 1) * sizeof(char));

            memcpy(ip, cur_ip_start, length);
            *(ip + length) = '\0';

            cc->address = str_replace(ip, "%gw", default_gw);
            free(ip);

            // try to load as sockaddr
            cc->sockaddr = calloc(1, sizeof(struct sockaddr_storage));
            int is_addr = to_sockaddr(cc->address, cc->sockaddr);

            if (is_addr) {
                print_debug(logger, "This is an address and is now stored: %s\n", cc->address);
            } else {
                cc->flags |= FLAG_IS_HOSTNAME;
            }

            // set initial connectivity_check values
            cc->state = STATE_NONE;

            int period;
            if (!config_lookup_int(&cfg, "period", &period))
            {
                print_error(logger, "%s is missing setting: period\n", cfg_path);
                config_destroy(&cfg);
                return 0;
            } else {
                cc->period = period; 
            }

            // timeout (can be an integer or double)
            int timeout;
            double timeout_dbl;
            if (config_lookup_int(&cfg, "timeout", &timeout)) {
                cc->timeout = (float) timeout;
            } else if (!config_lookup_float(&cfg, "timeout", &timeout_dbl))
            {
                print_error(logger, "%s is missing setting: timeout\n", cfg_path);
                config_destroy(&cfg);
                return 0;
            } else {
                cc->timeout = timeout_dbl;
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

            // loglevel configuration
            const char* setting_loglevel = NULL;
            if (config_lookup_string(&cfg, "loglevel", &setting_loglevel))
            {
                enum loglevel new_loglevel = to_loglevel(setting_loglevel);
                
                if (new_loglevel == INVALID_LOGLEVEL)
                {
                    print_error(logger, "%s contains unknown loglevel: %s\n", cfg_path, setting_loglevel);
                    config_destroy(&cfg);
                    return 0;
                }
                cc->loglevel = new_loglevel;
            } else {
                cc->loglevel = INVALID_LOGLEVEL;
            } 

            // check if this is "srd.conf" (config_main)
            if (ends_with(cfg_path, config_main)) {
#ifndef DEBUG
                // loglevel of srd
                if (cc->loglevel == INVALID_LOGLEVEL) {
                    print_error(logger, "No loglevel defined in %s.\n", cfg_path);
                    config_destroy(&cfg);

                    return 0;
                } else {
                    loglevel = to_loglevel(setting_loglevel);
                }
#else
                cc->loglevel = LOGLEVEL_DEBUG;
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
                int delay;
                if (!config_setting_lookup_int(action, "delay", &delay))
                {
                    this_action->delay = 0;
                } else {
                    this_action->delay = delay;
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

                    if (escaped_servicename == NULL) {
                        print_error(logger, "%s: Out of memory.\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    
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
                    command = str_replace(command, "%ip", (char *)cc->address);

                    const placeholder_t placeholder = {
                        .info = get_replacements(command),
                        .raw_message = command
                    };
                    cmd->cmd_ph = placeholder;

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

                        action_log->path = str_replace(path, "%ip", cc->address);

                        free((char*)path);
                    }

                    const char* message;
                    if (!config_setting_lookup_string(action, "message", &message))
                    {
                        print_error(logger, "%s: element is missing the message\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    placeholder_t placeholder = {
                        .info = get_replacements(message),
                        .raw_message = str_replace(message, "%ip", (char *)cc->address)
                    };
                    action_log->message_ph = placeholder;

                    // Load header
                    const char* header;
                    if (config_setting_lookup_string(action, "header", &header))
                    {
                        action_log->header = str_replace(header, "%ip", (char *)cc->address);
                    } else {
                        action_log->header = NULL;
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
                    action_influx->conn_epoll_read_fd = -1;
                    action_influx->conn_epoll_write_fd = -1;

                    // load the port
                    if (!config_setting_lookup_int(action, "port", &action_influx->port))
                    {
                        action_influx->port = 8086;
                    }

                    // load the host
                    const char* host;
                    if (!config_setting_lookup_string(action, "host", &host))
                    {
                        print_error(logger, "%s: element is missing the host\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->host = strdup(host);

                    action_influx->sockaddr = calloc(1, sizeof(struct sockaddr_storage));
                    int is_ip = to_sockaddr(host, action_influx->sockaddr);

                    if (is_ip) {
                        print_debug(logger, "This is an address and is now stored: %s\n", action_influx->host);

                        if (action_influx->sockaddr->ss_family == AF_INET) {
                            ((struct sockaddr_in*)action_influx->sockaddr)->sin_port = htons(action_influx->port);
                        } else {
                            ((struct sockaddr_in6*)action_influx->sockaddr)->sin6_port = htons(action_influx->port);
                        }
                    } else {
                        action_influx->flags |= FLAG_IS_HOSTNAME;
                    }
                    
                    // load the endpoint
                    const char* endpoint;
                    if (!config_setting_lookup_string(action, "endpoint", &endpoint))
                    {
                        print_error(logger, "%s: element is missing the endpoint\n", cfg_path);
                        config_destroy(&cfg);
                        return 0;
                    }
                    action_influx->endpoint = str_replace(endpoint, "%ip", cc->address);

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
                    placeholder_t placeholder = {
                        .raw_message = str_replace(linedata, "%ip", cc->address),
                        .info = get_replacements(linedata)
                    };
                    action_influx->line = placeholder;

                    // load timeout
                    if (!config_setting_lookup_int(action, "timeout", &action_influx->timeout)) {
                        action_influx->timeout = 2;
                    }

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
