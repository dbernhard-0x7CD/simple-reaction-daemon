#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <string.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <libconfig.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "srd.h"

char config_fpath[] = "/etc/srd/srd.conf";
const char version[] = "0.0.1";

#define LOGLEVEL_DEBUG 1
#define LOGLEVEL_INFO 2

#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN

#define print_debug(...)               \
    if (loglevel <= LOGLEVEL_DEBUG)    \
    {                                  \
        printf("DEBUG: " __VA_ARGS__); \
    }

#define print_info(...)            \
    if (loglevel <= LOGLEVEL_INFO) \
    {                              \
        printf(__VA_ARGS__);       \
    }

int running = 1;
int loglevel = LOGLEVEL_DEBUG;

int main()
{
    print_debug("Starting Simple Reconnect Daemon\n");

    // for stopping the service
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGKILL, signal_handler);
    signal(SIGSTOP, signal_handler);

    // load configuration
    config_t cfg;
    config_init(&cfg);

    if (access(config_fpath, F_OK))
    {
        printf("Missing config file at %s", config_fpath);
        fflush(stdout);
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    if (!config_read_file(&cfg, config_fpath))
    {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        fflush(stdout);
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    int count;
    const char *ip;
    int timeout;
    int period;
    action_t *actions;

    if (!load_config(&cfg, &ip, &period, &timeout, &count, &actions))
    {
        return EXIT_FAILURE;
    }

    print_debug("Amount of actions: %d\n", count);

    // data
    int ms_since_last_reply = 0;

    sd_bus *bus = NULL;
    int r;

    /* Connect to the system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0)
    {
        fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
        return EXIT_FAILURE;
    }

    printf("Starting srd (Simple Reconnect Daemon) version ");
    printf(version);
    printf("\n");
    printf("Target IP: %s\n", ip);
    printf("Period: %d\n", period);
    printf("Ping timeout: %d\n", timeout);
    printf("Loglevel: %d\n", loglevel);

    fflush(stdout);

    struct timespec stop, start;

    while (running)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);

        int connected = check_connectivity(ip, timeout);
        char *p;
        int len;
        time_t t = time(NULL);

        p = ctime(&t);
        len = strlen(p);

        if (connected == 1)
        {
            print_info("Still reachable %.*s\n\n\n", len - 1, p);
            ms_since_last_reply = 0;
        }
        else
        {
            clock_gettime(CLOCK_MONOTONIC_RAW, &stop);

            uint64_t delta_us = (stop.tv_sec - start.tv_sec) * 1000 + (stop.tv_nsec - start.tv_nsec) / 1000000;
            ms_since_last_reply += delta_us;

            print_info("Disconnected at %.*s; now for %dms\n", len - 1, p, ms_since_last_reply);
        }

        // check if any action is required
        for (int i = 0; i < count; i++)
        {
            if (actions[i].delay * 1000 <= ms_since_last_reply)
            {
                print_debug("Should do action: %s\n", actions[i].name);

                if (strcmp(actions[i].name, "service-restart") == 0)
                {
                    restart_service(actions[i].object);
                }
                else if (strcmp(actions[i].name, "reboot") == 0)
                {
                    restart_system();
                }
                else if (strcmp(actions[i].name, "command") == 0)
                {
                    int status = run_command(actions[i].object);
                    if (status < 0) {
                        break;
                    }
                }
                else
                {
                    printf("This action is NOT yet implemented: %s\n", actions[i].name);
                }
            }
        }

        fflush(stdout);

        sleep(period);
        ms_since_last_reply += period * 1000;
    }

    print_info("Shutting down Simple Reconnect Daemon\n");
    fflush(stdout);

    return EXIT_SUCCESS;
}

void signal_handler(int s)
{
    if (s == SIGTERM || s == SIGABRT || s == SIGKILL || s == SIGSTOP)
    {
        running = 0;
        return;
    }
    printf("Unhandled signal %d\n", s);
    fflush(stdout);
}

/*
* Sends a signal to restart the machine.
* Returns 1 on success else 0.
*/
int restart_system()
{
    print_info("Sending restart signal\n");
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    const char *path;
    int r;

    /* Connect to the system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0)
    {
        fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
        goto finish;
    }

    r = sd_bus_call_method(
        bus,
        "org.freedesktop.systemd1",         /* service to contact */
        "/org/freedesktop/systemd1",        /* object path */
        "org.freedesktop.systemd1.Manager", /* interface name */
        "Reboot",                           /* method name */
        &error,                             /* object to return error in */
        &m,                                 /* return message on success */
        "");
    if (r < 0)
    {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /* Parse the response message */
    r = sd_bus_message_read(m, "o", &path);
    if (r < 0)
    {
        fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    print_info("Reboot scheduled. Service job: %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? 0 : 1;
}

/*
 * Runs the given command.
 * Returns 1 if success, else 0.
 */
int run_command(const action_cmd_t *cmd)
{
    FILE *fp;
    char buf[1024];

    int id = fork();

    if (id < 0)
    {
        printf("Unable to fork.\n");
        return 0;
    }
    else if (id == 0)
    {
        // switch to user
        if (cmd->user != NULL)
        {
            struct passwd *a = getpwnam(cmd->user);
            uid_t uid = a->pw_uid;
            setuid(uid);
        }

        fp = popen(cmd->command, "r");
        if (fp == NULL)
        {
            printf("Failed to run command\n");
            return EXIT_FAILURE;
        }

        while (fgets(buf, sizeof(buf), fp) != NULL)
        {
            print_info("%s", buf);
        }

        pclose(fp);
        exit(0);
    }
    else
    {
        wait(NULL);
    }

    return 1;
}

/*
 * Checks if this machine is still able to ping the given IP.
 * Returns 1 if the IP is still reachable in the given timeout,
 * else 0. If we cannot determine connectivity a negative value
 * is returned
 */
int check_connectivity(const char *ip, int timeout)
{
    int pipefd[2];
    pipe(pipefd);

    int f = fork();
    if (f == 0) // I'm the child
    {
        int mypid = getpid();
        print_debug("I'm the child with pid %d\n", mypid);

        // close my stdout
        close(1);
        dup(pipefd[1]);

        close(pipefd[0]);

        int length = (int)((ceil(log10(1.0 * timeout)) + 1) * sizeof(char));
        char str[length];
        sprintf(str, "%d", timeout);

        execlp("ping", "ping",
               "-c", "1",
               "-w", str,
               ip, (char *)0);
        return 0;
    }
    else if (f < 0)
    {
        printf("Forking did not work\n");
        fflush(stdout);
        running = 0;

        return -1;
    }
    else
    {
        int status;
        wait(&status);

        close(pipefd[1]);
        close(pipefd[0]);

        return status == 0;
    }
}

// Loads the configuration in ip, period, timeout and global loglevel
// Returns 1 on success, else 0.
int load_config(config_t *cfg, const char **ip, int *period, int *timeout, int *count, action_t **actions)
{
    const char *setting_loglevel;
    config_setting_t *setting;

    if (!config_lookup_string(cfg, "destination", ip))
    {
        printf("missing setting: destination\n");
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_int(cfg, "period", period))
    {
        printf("missing setting: period\n");
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_int(cfg, "timeout", timeout))
    {
        printf("missing setting: timeout\n");
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_string(cfg, "loglevel", &setting_loglevel))
    {
        printf("missing setting: loglevel\n");
        config_destroy(cfg);
        return 0;
    }

    if (strcmp("INFO", setting_loglevel) == 0)
    {
        loglevel = LOGLEVEL_INFO;
    }
    else if (strcmp("DEBUG", setting_loglevel) == 0)
    {
        loglevel = LOGLEVEL_DEBUG;
    }
    else
    {
        printf("Unknown loglevel: %s\n", setting_loglevel);
        return 0;
    }

    // load the actions
    setting = config_lookup(cfg, "actions");
    if (setting == NULL)
    {
        printf("Missing actions in config file.\n");
        config_destroy(cfg);
        return 0;
    }
    *count = config_setting_length(setting);
    *actions = malloc(*count * sizeof(action_t));
    action_t *action_arr = *actions;

    for (int i = 0; i < *count; i++)
    {
        const config_setting_t *action = config_setting_get_elem(setting, i);

        const char *action_name;
        if (!config_setting_lookup_string(action, "action", &action_name))
        {
            printf("Element is missing the action\n");
            config_destroy(cfg);
            return 0;
        }
        action_arr[i].name = (char *)action_name;

        if (!config_setting_lookup_int(action, "delay", &action_arr[i].delay))
        {
            printf("Element is missing the delay\n");
            config_destroy(cfg);
            return 0;
        }

        if (strcmp(action_name, "reboot") == 0)
        {
            // nothing to do
        }
        else if (strcmp(action_name, "service-restart") == 0)
        {
            if (!config_setting_lookup_string(action, "name", (const char **)&action_arr[i].object))
            {
                printf("Element is missing the name\n");
                config_destroy(cfg);
                return 0;
            }

            char* escaped_servicename = escape_servicename((char *)action_arr[i].object);
            print_debug("Escaped to %s\n", escaped_servicename);
            action_arr[i].object = escaped_servicename;
        }
        else if (strcmp(action_name, "command") == 0)
        {
            action_cmd_t *cmd = malloc(sizeof(action_cmd_t));

            if (!config_setting_lookup_string(action, "cmd", (const char **)&cmd->command))
            {
                printf("Element is missing the cmd\n");
                config_destroy(cfg);
                return 0;
            }

            if (!config_setting_lookup_string(action, "user", (const char **)&cmd->user))
            {
                cmd->user = NULL;
            }

            action_arr[i].object = cmd;
        }
        else
        {
            printf("Unknown element in configuration on line %d\n", action->line);
            return 0;
        }
    }

    return 1;
}

/*
 * Restarts the service with the given name.
 * Returns 1 on success, else 0.
 */
int restart_service(char *name)
{
    print_debug("Restart service %s\n", name);

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    const char *path;
    int r;

    /* Connect to the system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0)
    {
        fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
        goto finish;
    }
    char service_name[256];
    char *prefix = "/org/freedesktop/systemd1/unit/";
    int len = strlen(prefix);
    strcpy(service_name, prefix);
    strcpy(service_name + len, name);

    print_debug("Object path: %s\n", service_name);

    r = sd_bus_call_method(
        bus,
        "org.freedesktop.systemd1",      /* service to contact */
        service_name,                    /* object path */
        "org.freedesktop.systemd1.Unit", /* interface name */
        "Restart",                       /* method name */
        &error,                          /* object to return error in */
        &m,                              /* return message on success */
        "s",                             /* input signature */
        "fail");
    if (r < 0)
    {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /* Parse the response message */
    r = sd_bus_message_read(m, "o", &path);
    if (r < 0)
    {
        fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    print_debug("Queued service job as %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? 0 : 1;
}

int needs_escaping(char c) {
    if (!(c >= 48 && c <= 57) && !(c >= 65 && c <= 90) && !(c >= 97 && c <= 122)) {
        return 1;
    }

    return 0;
}

/*
* Accepts a service name and returns the same service name escaped.
* Each character not in [a-Z] or [0-9] will get escaped to '_HEX' where HEX is
* the HEX value of the value
*/
char* escape_servicename(char* input_name) {
    // count characters which need escaping
    char* start = input_name;
    int chars_need_escaping = 0;
    int len = strlen(input_name);

    while(*start != '\0') {
        char v = *start;

        if (needs_escaping(v)) {
            chars_need_escaping++;
        }
        start++;
    }

    int new_len = len + 1 + chars_need_escaping*2;
    char* escaped_str = (char*)malloc(new_len);

    if (escaped_str == NULL) {
        printf("Out of memory\n");
        exit(1);
    }

    int new_i = 0;
    for (int i = 0; i < len; i++) {
        char old = input_name[i];

        if (needs_escaping(old)) {
            char buf[2];
            sprintf(buf, "%x", old);
            
            escaped_str[new_i] = '_';
            escaped_str[new_i+1] = buf[0];
            escaped_str[new_i+2] = buf[1];
            new_i += 3;
        } else {
            escaped_str[new_i] = old;
            new_i++;
        }
    }

    return escaped_str;
}
