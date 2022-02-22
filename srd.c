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
#include <sys/stat.h>
#include <sys/time.h>

#include "srd.h"

char config_fpath[] = "/etc/srd/srd.conf";
const char version[] = "0.0.1";

#define DEBUG 1

#define LOGLEVEL_DEBUG 1
#define LOGLEVEL_INFO 2

#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN

#define print_debug(...) \
if (loglevel <= LOGLEVEL_DEBUG) { \
    printf("DEBUG: " __VA_ARGS__); \
}

#define print_info(...) \
if (loglevel <= LOGLEVEL_INFO) { \
    printf(__VA_ARGS__); \
}

int running = 1;
int loglevel = 1;

void signal_handler(int);

int main()
{
    print_debug("Starting Simple Reconnect Daemon\n");
    
    // ensure we have the rights to restart services (or the machine)
    if (has_root_access() == 0) {
        printf("I do not have root access to restart the machine\n");
        return EXIT_FAILURE;
    }

    // for stopping the service
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGKILL, signal_handler);
    signal(SIGSTOP, signal_handler);

    // load configuration
    config_t cfg;
    config_init(&cfg);

    if (access(config_fpath, F_OK)) {
        printf("Missing config file at %s", config_fpath);
        fflush(stdout);
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    if (!config_read_file(&cfg, config_fpath)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
        fflush(stdout);
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    int count;
    const char *ip;
    int timeout;
    int freq;
    action_t *actions;

    if(load_config(&cfg, &ip, &freq, &timeout, &count, &actions)) {
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
    printf("Frequency: %d\n", freq);
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
            print_info("Still reachable %.*s\n\n\n", len -1, p);
            ms_since_last_reply = 0;
        }
        else
        {
            clock_gettime(CLOCK_MONOTONIC_RAW, &stop);

            uint64_t delta_us = (stop.tv_sec - start.tv_sec) * 1000 + (stop.tv_nsec - start.tv_nsec) / 1000000;
            ms_since_last_reply += delta_us;

            print_info("Disconnected at %.*s; now for %dms\n\n", len -1, p, ms_since_last_reply);
        }

        // check if any action is required
        for (int i = 0; i < count; i++) {
            if (actions[i].delay * 1000 <= ms_since_last_reply) {
                print_debug("Should do action: %s\n", actions[i].name);

                if (strcmp(actions[i].name, "service-restart") == 0) {
                    restart_service(actions[i].object);
                } else if (strcmp(actions[i].name, "reboot") == 0) {
                    restart_system();
                } else if (strcmp(actions[i].name, "command") == 0) {
                    run_command("echo 1 >> /home/david/test", "");
                } else {
                    printf("This action is NOT yet implemented: %s\n", actions[i].name);
                }
            }
        }

        fflush(stdout);

        sleep(freq);
        ms_since_last_reply += freq * 1000;
    }

    print_info("Shutting down Simple Reconnect Daemon\n");
    fflush(stdout);

    return EXIT_SUCCESS;
}

int has_root_access() {
    int me = getegid();
    int effective_gid = getegid();
    print_debug("my gid: %d; effective gid: %d\n", me, effective_gid);

    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/etc/group", "r");
    if (fp == NULL) {
        printf("Unable to read /etc/group");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    char buf[10]; // log_10(2^32)
    sprintf(buf, "%d", effective_gid);
    printf("buf: %s\n", buf);

    while ((read = getline(&line, &len, fp)) != -1) {
        int gname = 0; // starts at beginning of the line
        int pwd = strcspn(line, ":");
        int gid = pwd + 1 + strcspn(line + pwd + 1, ":");
        int thrd = gid + 1 + strcspn(line + gid + 1, ":");

        *(line + thrd) = '\0';

        if (strcmp(line + gid + 1, buf) == 0) {
            // printf("found line: %s\n", line);
            if (strstr(line + thrd + 1, "root") == NULL) {
                print_debug("not root\n");
                fclose(fp);
                if (line) {
                    free(line);
                }
                return 0;
            }

            fclose(fp);
            if (line) {
                free(line);
            }
            return 1;
        }

        print_debug("first: %d; second %d; third: %d\n", pwd, gid, thrd);
    }

    fclose(fp);
    if (line) {
        free(line);
    }

    return 0;
}

void signal_handler(int s)
{
    if (s == SIGTERM || s == SIGABRT || s == SIGKILL || s == SIGSTOP) {
        running = 0;
        return;
    }
    printf("Unhandled signal %d\n", s);
    fflush(stdout);
}

int restart_system() {
    printf("Sending restart signal\n");
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
        "org.freedesktop.systemd1.Manager",    /* interface name */
        "Reboot",                          /* method name */
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

    printf("Reboot scheduled. Service job: %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

int run_command(const char* cmd, const char* user) {
    FILE *fp;
    char buf[1024];

    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        return EXIT_FAILURE;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        print_info("%s", buf);
    }

    pclose(fp);
        
    return 0;
}

int check_connectivity(const char* ip, int timeout)
{
    int pipefd[2];
    pipe(pipefd);

    int f = fork();
    if (f == 0) // I'm the child
    {
        int mypid = getpid();
        printf("I'm the child with pid %d\n", mypid);

        // close my stdout
        close(1);
        dup(pipefd[1]);

        close(pipefd[0]);

        int length = (int)((ceil(log10(1.0* timeout))+1)*sizeof(char));
        char str[length];
        sprintf(str, "%d", timeout);

        execlp("ping", "ping", 
                    "-c", "1",
                    "-w", str,
                    ip, (char *)0);
    }
    else if (f < 0)
    {
        printf("Forking did not work\n");
        fflush(stdout);
        running = 0;
    }
    else
    {
        int status;
        int res = wait(&status);

        print_debug("finished child process %d with status %d\n", res, status);

        close(pipefd[1]);
        close(pipefd[0]);

        return status == 0;
    }
    return 1;
}

// loads the configuration in ip, freq, timeout and global loglevel
int load_config(config_t *cfg, const char **ip, int *freq, int *timeout, int* count, action_t **actions) {
    const char* setting_loglevel;
    config_setting_t *setting;

    if (!config_lookup_string(cfg, "destination", ip)) {
        printf("missing setting: destination\n");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    if (!config_lookup_int(cfg, "frequency", freq)) {
        printf("missing setting: freq\n");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    if (!config_lookup_int(cfg, "timeout", timeout)) {
        printf("missing setting: timeout\n");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    if (!config_lookup_string(cfg, "loglevel", &setting_loglevel)) {
        printf("missing setting: loglevel\n");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }

    if (strcmp("INFO", setting_loglevel) == 0) {
        loglevel = LOGLEVEL_INFO;
    } else if (strcmp("DEBUG", setting_loglevel) == 0) {
        loglevel = LOGLEVEL_DEBUG;
    } else {
        printf("Unknown loglevel: %s\n", setting_loglevel);
        return EXIT_FAILURE;
    }

    // load the actions
    setting = config_lookup(cfg, "actions");
    if (setting == NULL) {
        printf("Missing actions in config file.\n");
        config_destroy(cfg);
        return EXIT_FAILURE;
    }
    *count = config_setting_length(setting);
    *actions = malloc(*count * sizeof(action_t));
    action_t *action_arr = *actions;

    for (int i = 0; i < *count; i++) {
        const config_setting_t *action = config_setting_get_elem(setting, i);

        const char* action_name;
        if (!config_setting_lookup_string(action, "action", &action_name)) {
            printf("Element is missing the action\n");
            config_destroy(cfg);
            return EXIT_FAILURE;
        }
        action_arr[i].name = (char *)action_name;

        if (!config_setting_lookup_int(action, "delay", &action_arr[i].delay)) {
            printf("Element is missing the delay\n");
            config_destroy(cfg);
            return EXIT_FAILURE;
        }

        if (strcmp(action_name, "reboot") == 0) {
            // all done
        } else if (strcmp(action_name, "service-restart") == 0) {
            
            if (!config_setting_lookup_string(action, "name", &action_arr[i].object)) {
                printf("Element is missing the name\n");
                config_destroy(cfg);
                return EXIT_FAILURE;
            }
        } else if (strcmp(action_name, "command") == 0) {
            // accept. TODO user, cmd
            if (!config_setting_lookup_string(action, "cmd", &action_arr[i].object)) {
                printf("Element is missing the cmd\n");
                config_destroy(cfg);
                return EXIT_FAILURE;
            }
        } else {
            printf("Unknown element in configuration on line %d\n", action->line);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

int restart_service(char* name)
{
#if DEBUG
    print_debug("Restart service %s\n", name);
#endif
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
        "org.freedesktop.systemd1",       /* service to contact */
        service_name,                     /* object path */
        "org.freedesktop.systemd1.Unit",  /* interface name */
        "Restart",                        /* method name */
        &error,                           /* object to return error in */
        &m,                               /* return message on success */
        "s",                              /* input signature */
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

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
