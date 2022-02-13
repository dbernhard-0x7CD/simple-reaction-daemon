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
#define LOGLEVEL_INFO 0

#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN

typedef struct action_t {
    const char*   name;
    const char*   object;
    int     delay;
} action_t;

int running = 1;

void signal_handler(int s)
{
    printf("i received signal %d\n", s);
    fflush(stdout);
    // TODO for shutting down, restarting
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
        "s",                                /* input signature */
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

    printf("Reboot scheduled. Service job: %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
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
        printf("forking did not work\n");
        fflush(stdout);
        exit(1);
    }
    else
    {
        int status;
        int res = wait(&status);

#if DEBUG
        printf("finished child process %d with status %d\n", res, status);
#endif

        close(pipefd[1]);
        close(pipefd[0]);

        return status == 0;
    }
    return 1;
}

int main()
{
    signal(SIGHUP, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGKILL, signal_handler);

    // load configuration
    int count;
    config_t cfg;
    config_setting_t *setting;
    config_init(&cfg);

    if (access(config_fpath, F_OK)) {
        printf("missing config file at %s", config_fpath);
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

    const char *ip;
    int timeout;
    int freq;
    const char *loglevel;

    if (!config_lookup_string(&cfg, "destination", &ip)) {
        printf("missing setting: destination\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    if (!config_lookup_int(&cfg, "frequency", &freq)) {
        printf("missing setting: freq\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    if (!config_lookup_int(&cfg, "timeout", &timeout)) {
        printf("missing setting: timeout\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }

    // load the actions
    setting = config_lookup(&cfg, "actions");
    if (setting == NULL) {
        printf("missing actions in config file.\n");
        config_destroy(&cfg);
        return EXIT_FAILURE;
    }
    count = config_setting_length(setting);
    printf("amount of actions: %d\n", count);
    action_t actions[count];

    for (int i = 0; i < count; i++) {
        const config_setting_t *action = config_setting_get_elem(setting, i);

        const char* action_name;
        if (!config_setting_lookup_string(action, "action", &action_name)) {
            printf("Element is missing the action\n");
            config_destroy(&cfg);
            return EXIT_FAILURE;
        }
        actions[i].name = (char *)action_name;

        if (strcmp(action_name, "reboot") == 0) {
            if (!config_setting_lookup_int(action, "delay", &actions[i].delay)) {
                printf("Element is missing the delay\n");
                config_destroy(&cfg);
                return EXIT_FAILURE;
            }
        } else { // must be service-restart
            if (!config_setting_lookup_int(action, "delay", &actions[i].delay)) {
                printf("Element is missing the delay\n");
                config_destroy(&cfg);
                return EXIT_FAILURE;
            }
            if (!config_setting_lookup_string(action, "name", &actions[i].object)) {
                printf("Element is missing the name\n");
                config_destroy(&cfg);
                return EXIT_FAILURE;
            }
        }
    }

    // data
    int ms_since_last_reply = 0;

    sd_bus *bus = NULL;
    const char *path;
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
#if DEBUG
            printf("still reachable %.*s\n\n\n", len -1, p);
#endif
            ms_since_last_reply = 0;
        }
        else
        {
            clock_gettime(CLOCK_MONOTONIC_RAW, &stop);

            uint64_t delta_us = (stop.tv_sec - start.tv_sec) * 1000 + (stop.tv_nsec - start.tv_nsec) / 1000000;
            ms_since_last_reply += delta_us;

            printf("disconnected at %.*s; now for %dms\n\n", len -1, p, ms_since_last_reply);
        }

        // check if any action is required
        for (int i = 0; i < count; i++) {
            if (actions[i].delay * 1000 <= ms_since_last_reply) {
                printf("should do action: %s\n", actions[i].name);

                if (strcmp(actions[i].name, "service-restart") == 0) {
                    restart_service(actions[i].object);
                } else if (strcmp(actions[i].name, "reboot") == 0) {
                    restart_system();
                }
            }
        }

        fflush(stdout);

        sleep(freq);
        ms_since_last_reply += freq * 1000;
    }

    return 0;
}

int restart_service(char* name)
{
#if DEBUG
    printf("restart_service %s\n", name);
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

    printf("object path: %s\n", service_name);
    

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

    printf("Queued service job as %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
