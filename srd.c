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
#include <fts.h>
#include <pthread.h>
#include <errno.h>

#include "srd.h"

char *const configd_path = "/etc/srd/";
char *const config_main = "/etc/srd/main.conf";
char *const version = "0.0.1";

#define LOGLEVEL_DEBUG 1
#define LOGLEVEL_INFO 2
#define DEBUG 0

#define print(...)                            \
    if (pthread_mutex_lock(&stdout_mut) != 0) \
    {                                         \
        perror("mutex_lock");                 \
        exit(1);                              \
    }                                         \
    printf(__VA_ARGS__);                      \
    pthread_mutex_unlock(&stdout_mut);

#define print_debug(...)              \
    if (loglevel <= LOGLEVEL_DEBUG)   \
    {                                 \
        print("DEBUG: " __VA_ARGS__); \
    }

#define print_info(...)              \
    if (loglevel <= LOGLEVEL_INFO)   \
    {                                \
        print("INFO: " __VA_ARGS__); \
    }

int running = 1;
int loglevel = LOGLEVEL_DEBUG;

// used to lock stdout as all threads write to it
pthread_mutex_t stdout_mut;

int main()
{
    print_debug("Starting Simple Reconnect Daemon\n");

    if (pthread_mutex_init(&stdout_mut, NULL) != 0)
    {
        fprintf(stderr, "Unable to initialize mutex\n");
        fflush(stderr);
        exit(1);
    }

    // load configuration files for connectivity targets
    int success = 1;
    int connectivity_targets = 0;
    connectivity_check_t **connectivity_checks = load(configd_path, &success, &connectivity_targets);
    if (!success)
    {
        return EXIT_FAILURE;
    }
    if (connectivity_checks == NULL)
    {
        fprintf(stderr, "Unable to load configuration\n");
        fflush(stderr);
        return EXIT_FAILURE;
    }

    print_debug("Amount of actions: %d\n", connectivity_targets);

    print_info("Starting srd (Simple Reconnect Daemon) version %s\n", version);
    print_info("Connectivity Targets: %d\n", connectivity_targets);
    fflush(stdout);

    pthread_t threads[connectivity_targets];

    // for each target in `connectivity_checks` we create one thread
    for (int i = 0; i < connectivity_targets; i++)
    {
        pthread_create(&threads[i], NULL, (void *)run_check, (void *)connectivity_checks[i]);
    }

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

        print_info("Awaiting shutdown signal\n");

        // waits until a signal arrives
        int result = sigwaitinfo(&waitset, &info);
        running = 0;

        if (result > 0) // returns caught signal
        {
            print_debug("Got signal %d\n", info.si_signo);
        }
        else
        {
            print_info("Sigwaitinfo failed with errno: %d, result: %d\n", errno, result);
            exit(-1);
        }
    }

    print_info("Shutting down Simple Reconnect Daemon\n");
    fflush(stdout);

    // kill and join all threads
    for (int i = connectivity_targets - 1; i >= 0; i--)
    {
        pthread_kill(threads[i], SIGALRM);
    }

    for (int i = connectivity_targets - 1; i >= 0; i--)
    {
        pthread_join(threads[i], NULL);
    }

    print_debug("Killed all threads\n");

    print_info("Finished Simple Reconnect Daemon.\n");
    fflush(stdout);

    // free
    // TODO with valgrind

    return EXIT_SUCCESS;
}

void run_check(connectivity_check_t *cc)
{
    // await alarm signal, then we stop
    signal(SIGALRM, signal_handler);

    sd_bus *bus = NULL;
    int retval;

    /* Connect to the system bus */
    retval = sd_bus_open_system(&bus);
    if (retval < 0)
    {
        print("Failed to connect to system bus: %s\n", strerror(-retval));
        return;
    }

    connectivity_check_t check = *cc;

    struct timespec now;

    const char *ip = check.ip;
    int timeout = check.timeout;

    clock_gettime(CLOCK_MONOTONIC_RAW, &check.timestamp_last_reply);

    // check connectivity repeatedly
    while (running)
    {
        int connected = check_connectivity(ip, timeout);
        char *p;
        int len;
        time_t t = time(NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &now);

        p = ctime(&t);
        len = strlen(p);

        double diff; // in ms
        if (connected == 1)
        {
            print_info("[%s]: Still reachable %.*s\n", ip, len - 1, p);
            check.timestamp_last_reply = now;
            diff = 0;
        }
        else
        {
            double_t delta_ms = (now.tv_sec - check.timestamp_last_reply.tv_sec) + (now.tv_nsec - check.timestamp_last_reply.tv_nsec) / 1000000000.0;

            print_info("[%s]: NOT reachable at %.*s; now for %0.3fs\n", ip, len - 1, p, delta_ms);
            diff = delta_ms;
        }
        fflush(stdout);

        // check if any action is required
        for (int i = 0; i < check.count; i++)
        {
            if (check.actions[i].delay <= diff)
            {
                print_debug("[%s]: Should do action: %s\n", check.ip, check.actions[i].name);

                if (strcmp(check.actions[i].name, "service-restart") == 0)
                {
                    restart_service(check.actions[i].object, check.ip);
                }
                else if (strcmp(check.actions[i].name, "reboot") == 0)
                {
                    restart_system(check.ip);
                }
                else if (strcmp(check.actions[i].name, "command") == 0)
                {
                    action_cmd_t *cmd = check.actions[i].object;
                    print_debug("\tCommand: %s\n", cmd->command)

                        int status = run_command(check.actions[i].object);
                    if (status < 0)
                    {
                        continue;
                    }
                }
                else
                {
                    print_info("This action is NOT yet implemented: %s\n", check.actions[i].name);
                }
            }
        } // end check if any action has to be taken

        print_debug("[%s]: Sleeping for %d seconds...\n\n", check.ip, check.period);
        fflush(stdout);

        sleep(check.period);
    }
}

void signal_handler(int s)
{
    if (s == SIGTERM || s == SIGABRT || s == SIGKILL || s == SIGSTOP || s == SIGALRM)
    {
        running = 0;
        return;
    }
    printf("Unhandled signal %d\n", s);
    fflush(stdout);
}

int restart_system(const char *ip)
{
    print_info("[%s]: Sending restart signal\n", ip);
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

    print_info("[%s]: Reboot scheduled. Service job: %s.\n", ip, path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? 0 : 1;
}

int run_command(const action_cmd_t *cmd)
{
    FILE *fp;
    char buf[1024];

    int pid = fork();

    if (pid < 0)
    {
        printf("Unable to fork.\n");
        return 0;
    }
    else if (pid == 0)
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

    print_debug("[%s]: Checking connectivity\n", ip);

    int pid = fork();
    if (pid == 0) // child
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
               "-W", str,
               ip, (char *)0);
        return 0;
    }
    else if (pid < 0) // failed
    {
        printf("Forking did not work\n");
        fflush(stdout);
        running = 0;

        return -1;
    }
    else // i'm the parent
    {
        int status, ret, err;
        do
        {
            ret = waitpid(pid, &status, NULL);
            err = errno;
        } while ((ret == -1) && (err == EINTR));
        
        close(pipefd[1]);

        if (ret == -1)
        {
            print_debug("Unable to ping. errno is %d\n", errno);
        }

#if DEBUG
        // print stdout of child (which pinged the target)

        if (pthread_mutex_lock(&stdout_mut) != 0)
        {
            perror("mutex_lock");
            return -1;
        }

        char buffer[4096];
        while (1)
        {
            ssize_t count = read(pipefd[0], buffer, sizeof(buffer));
            if (count == -1)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                else
                {
                    perror("read");
                    return -1;
                }
            }
            else if (count == 0)
            {
                break;
            }
            else
            {
                printf(buffer);
            }
        }
        pthread_mutex_unlock(&stdout_mut);
#endif

        close(pipefd[0]);

        int success = status == 0;

        print_debug("[%s] Ping has success: %d\n", ip, success);

        return success;
    }
}

connectivity_check_t **load(char *directory, int *success, int *count)
{
    FTS *fts_ptr;
    FTSENT *p, *children_ptr;
    int opt = FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR;
    int children_count = 0;
    connectivity_check_t **conns = malloc(10 * sizeof(connectivity_check_t *));

    char *args[2];
    args[0] = "/etc/srd";
    args[1] = NULL;

    if ((fts_ptr = fts_open(args, opt, NULL)) == NULL)
    {
        printf("Unable to read directory %s\n", directory);
        *success = 0;
        return NULL;
    }

    children_ptr = fts_children(fts_ptr, 0);
    if (children_ptr == NULL)
    {
        printf("No config files at %s\n", configd_path);
        fflush(stdout);
        *success = 0;
        return NULL;
    }

    while ((p = fts_read(fts_ptr)) != NULL)
    {
        if (p->fts_info == FTS_F)
        {
            config_t cfg;
            config_init(&cfg);
            printf("visiting path %s\n", p->fts_path);

            // TODO: only accept if the path ends with '.conf'

            if (!config_read_file(&cfg, p->fts_path))
            {
                fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
                fflush(stderr);
                config_destroy(&cfg);
                *success = 0;
                return NULL;
            }

            print_debug("Read config file %s\n", p->fts_path);

            connectivity_check_t *check = malloc(sizeof(connectivity_check_t));

            if (!load_config(&cfg, &check->ip, &check->period, &check->timeout, &check->count, &check->actions))
            {
                printf("Unable to load config %s\n", p->fts_path);
                *success = 0;
                return NULL;
            }

            conns[children_count] = check;

            children_count++;
        }
    }
    if (children_count == 0)
    {
        printf("Missing config file at %s\n", configd_path);
        fflush(stdout);
        *success = 0;
        return NULL;
    }
    fts_close(fts_ptr);

    *success = 1;
    *count = children_count;

    return conns;
}

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
        print_info("Missing actions in config file.\n");
        config_destroy(cfg);
        return 0;
    }
    *count = config_setting_length(setting);
    *actions = malloc(*count * sizeof(action_t));
    action_t *const action_arr = *actions;

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

            char *escaped_servicename = escape_servicename((char *)action_arr[i].object);
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

int restart_service(const char *name, const char *ip)
{
    print_debug("[%s]: Restart service %s\n", ip, name);

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

    print_debug("[%s]: Queued service job as %s.\n", ip, path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? 0 : 1;
}

int needs_escaping(char c)
{
    if (!(c >= 48 && c <= 57) && !(c >= 65 && c <= 90) && !(c >= 97 && c <= 122))
    {
        return 1;
    }

    return 0;
}

char *escape_servicename(char *input_name)
{
    // count characters which need escaping
    char *start = input_name;
    int chars_need_escaping = 0;
    int len = strlen(input_name);

    while (*start != '\0')
    {
        char v = *start;

        if (needs_escaping(v))
        {
            chars_need_escaping++;
        }
        start++;
    }

    int new_len = len + 1 + chars_need_escaping * 2;
    char *escaped_str = (char *)malloc(new_len);

    if (escaped_str == NULL)
    {
        printf("Out of memory\n");
        exit(1);
    }

    int new_i = 0;
    for (int i = 0; i < len; i++)
    {
        char old = input_name[i];

        if (needs_escaping(old))
        {
            char buf[2];
            sprintf(buf, "%x", old);

            escaped_str[new_i] = '_';
            escaped_str[new_i + 1] = buf[0];
            escaped_str[new_i + 2] = buf[1];
            new_i += 3;
        }
        else
        {
            escaped_str[new_i] = old;
            new_i++;
        }
    }

    return escaped_str;
}
