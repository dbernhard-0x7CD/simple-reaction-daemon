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
char *const config_main = "/srd.conf";
char *const version = "0.0.1-dev";

int loglevel = LOGLEVEL_DEBUG;

/* Define some macros to print inside a mutex */
#define print(...)                            \
    if (pthread_mutex_lock(&stdout_mut) != 0) \
    {                                         \
        perror("Failed to lock mutex\n");     \
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

/* used to exit the main loop and stop all threads */
int running = 1;

/* used to lock stdout as all threads write to it */
pthread_mutex_t stdout_mut;

int main()
{
    print_info("Starting Simple Reconnect Daemon\n");

    // create a mutex; if unsuccessful we stop
    if (pthread_mutex_init(&stdout_mut, NULL) != 0)
    {
        fprintf(stderr, "Unable to initialize mutex\n");
        fflush(stderr);
        exit(1);
    }

    // load configuration files for connectivity targets
    int success = 0;
    int connectivity_targets = 0;
    connectivity_check_t **connectivity_checks = load(configd_path, &success, &connectivity_targets);
    if (!success || connectivity_checks == NULL)
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
    check_arguments_t args[connectivity_targets];

    // Start threads for each connectivity target
    // for each target in `connectivity_checks` we create one thread
    for (int i = 0; i < connectivity_targets; i++)
    {
        args[i] = (check_arguments_t) { connectivity_checks, i, connectivity_targets };
        pthread_create(&threads[i], NULL, (void *)run_check, (void *)&args[i]);
    }

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
    for (int i = 0; i < connectivity_targets; i++)
    {
        pthread_kill(threads[i], SIGALRM);
    }

    for (int i = 0; i < connectivity_targets; i++)
    {
        pthread_join(threads[i], NULL);
    }

    print_debug("Killed all threads\n");

    print_info("Finished Simple Reconnect Daemon.\n");
    fflush(stdout);

    // free all memory
    for (int i = 0; i < connectivity_targets; i++) {
        connectivity_check_t* ptr = connectivity_checks[i];

        config_destroy(&ptr->config);

        // free cmd if it is a command (contains the command) or service-restart (contains service name)
        for (int i = 0; i < ptr->count; i++) {
            if (strcmp(ptr->actions[i].name, "command") == 0 ||
                strcmp(ptr->actions[i].name, "service-restart") == 0) {
                free(ptr->actions[i].object);
            }
        }
        free(ptr->actions);
        free(ptr);
    }
    free(connectivity_checks);

    return EXIT_SUCCESS;
} // main end

int is_available(connectivity_check_t **ccs, const int n, char const *ip, int strict) {
    for (int i = 0; i < n; i++) {
        connectivity_check_t* ptr = ccs[i];

        if (strcmp(ip, ptr->ip) == 0) {
            if (ptr->status == STATUS_SUCCESS) {
                return 1;
            }
            if (ptr->status == STATUS_NONE && strict == 0) {
                return 1;
            }

            print_debug("Not available: %s %d\n", ptr->ip, ptr->status);
            return 0;
        }
    }

    print_info("This dependency does not have a check: %s\n", ip);
    return 0;
}

void run_check(check_arguments_t *args)
{
    // await alarm signal, then we stop
    signal(SIGALRM, signal_handler);

    int idx = args->idx;
    connectivity_check_t* check = args->connectivity_checks[idx];

    // store time to calculate how long a ping took
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &check->timestamp_last_reply);

    // main loop: check connectivity repeatedly
    while (running)
    {
        // check if our dependency is available
        if (check->depend_ip != NULL) {
            print_debug("[%s]: Checking for dependency %s\n",check->ip, check->depend_ip);

            int available = is_available(args->connectivity_checks, args->amount_targets, check->depend_ip, 1);

            if (available == 0) {
                print_info("[%s]: Awaiting dependency %s\n", check->ip, check->depend_ip);
                sleep(check->period);
                continue;
            }
        }

        int connected = check_connectivity(check->ip, check->timeout);
        char *p;
        int len;
        time_t t = time(NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &now);

        p = ctime(&t);
        len = strlen(p);

        double diff; // in ms
        if (connected == 1)
        {
            if (check->status != STATUS_SUCCESS) {
                print_info("[%s]: Reachable %.*s\n", check->ip, len - 1, p);
                check->status = STATUS_SUCCESS;
            }
            check->timestamp_last_reply = now;
            diff = 0;
        }
        else
        {
            double_t delta_ms = (now.tv_sec - check->timestamp_last_reply.tv_sec) + (now.tv_nsec - check->timestamp_last_reply.tv_nsec) / 1000000000.0;

            if (check->status != STATUS_FAILED) {
                print_info("[%s]: NOT reachable at %.*s; now for %0.3fs\n", check->ip, len - 1, p, delta_ms);
                check->status = STATUS_FAILED;
            }
            
            diff = delta_ms;
        }
        fflush(stdout);

        // check if any action is required
        for (int i = 0; i < check->count; i++)
        {
            if (check->actions[i].delay <= diff)
            {
                print_debug("[%s]: Should do action: %s\n", check->ip, check->actions[i].name);

                if (strcmp(check->actions[i].name, "service-restart") == 0)
                {
                    restart_service(check->actions[i].object, check->ip);
                }
                else if (strcmp(check->actions[i].name, "reboot") == 0)
                {
                    restart_system(check->ip);
                }
                else if (strcmp(check->actions[i].name, "command") == 0)
                {
                    action_cmd_t *cmd = check->actions[i].object;
                    print_debug("\tCommand: %s\n", cmd->command)

                    int status = run_command(check->actions[i].object);
                    if (status < 0)
                    {
                        continue;
                    }
                }
                else
                {
                    print_info("This action is NOT yet implemented: %s\n", check->actions[i].name);
                }
            }
        } // end check if any action has to be taken

        print_debug("[%s]: Sleeping for %d seconds...\n\n", check->ip, check->period);
        fflush(stdout);

        if (running) {
            sleep(check->period);
        }
    }
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

int restart_system(const char *ip)
{
    print_info("[%s]: Sending restart signal\n", ip);
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *msg = NULL;
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
        &msg,                               /* return message on success */
        "");
    if (r < 0)
    {
        fprintf(stderr, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /* Parse the response message */
    r = sd_bus_message_read(msg, "o", &path);
    if (r < 0)
    {
        fprintf(stderr, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    print_info("[%s]: Reboot scheduled. Service job: %s.\n", ip, path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(msg);
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
            print_info("Command output: %s", buf);
        }

        pclose(fp);
        exit(0);
    }
    else
    {
        // await child
        waitpid(pid, NULL, WNOHANG);
    }

    return 1;
}

int check_connectivity(const char *ip, int timeout)
{
    int pipefd[2];
    pipe(pipefd);

    print_debug("[%s]: Checking connectivity\n", ip);

    int pid = fork();
    if (pid == 0) // child
    {
        int mypid = getpid();
        print_debug("[%s]: I'm the child with pid %d\n", ip, mypid);

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
    else
    {
        // await my child
        int status, ret;
        while ((ret = waitpid(pid, &status, WUNTRACED)) == -1) {
            if (errno == EINTR) {
                printf("Got interrupted\n");
                sleep(1);
                continue;
            } else {
                printf("error %d\n", errno);
                break;
            }
        };
        
        close(pipefd[1]);

        if (ret == -1)
        {
            print_debug("Unable to ping. errno is %d\n", errno);
        }

        close(pipefd[0]);

        int success = status == 0;

        print_debug("[%s]: Ping has success: %d\n", ip, success);

        return success;
    }
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
            // only accept if the path ends with '.conf'
            if (!ends_with(p->fts_path, ".conf")) {
                continue;
            }

            print_info("Read config file %s\n", p->fts_path);

            connectivity_check_t *check = malloc(sizeof(connectivity_check_t));

            if (!load_config(p->fts_path, check, &check->config))
            {
                print("Unable to load config %s\n", p->fts_path);
                *success = 0;
                return NULL;
            }

            // initial connectivity_check values
            check->status = STATUS_NONE;

            // check if we need more space in conns
            if (cur_size >= cur_max) {
                cur_max += 8;
                printf("increasing\n");
                conns = realloc(conns, cur_max * sizeof(connectivity_check_t *));

                if (conns == NULL) {
                    printf("Out of memory\n");

                    *success = 0;
                    fts_close(fts_ptr);
                    return NULL;
                }
            }

            conns[cur_size] = check;

            print_debug("Just loaded connectivity check for target %s\n", conns[cur_size]->ip);
            cur_size++;
        }
    }

    // if no configuration files were found
    if (cur_size == 0)
    {
        printf("Missing config file at %s\n", configd_path);
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

int load_config(char *cfg_path, connectivity_check_t* cc, config_t* cfg)
{
    config_init(cfg);

    if (!config_read_file(cfg, cfg_path))
    {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg), config_error_line(cfg), config_error_text(cfg));
        fflush(stderr);
        config_destroy(cfg);
        
        return 0;
    }
    
    const char *setting_loglevel;
    config_setting_t *setting;

    if (!config_lookup_string(cfg, "destination", &cc->ip))
    {
        print_info("%s is missing setting: destination\n", cfg_path);
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_int(cfg, "period", &cc->period))
    {
        print_info("%s is missing setting: period\n", cfg_path);
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_int(cfg, "timeout", &cc->timeout))
    {
        print_info("%s is missing setting: timeout\n", cfg_path);
        config_destroy(cfg);
        return 0;
    }

    if (!config_lookup_string(cfg, "depends", &cc->depend_ip)) {
        cc->depend_ip = NULL;
    }

    if (ends_with(cfg_path, config_main)) {
        if (config_lookup_string(cfg, "loglevel", &setting_loglevel))
        {
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
                printf("%s contains unknown loglevel: %s\n", cfg_path, setting_loglevel);
                return 0;
            }
        } else {
            print_info("No loglevel defined in %s.\n", cfg_path);
        }
    } // end if for "srd.conf"

    // load the actions
    setting = config_lookup(cfg, "actions");
    if (setting == NULL)
    {
        print_debug("%s: missing actions in config file.\n", cfg_path);
        config_destroy(cfg);
        return 1;
    }
    cc->count = config_setting_length(setting);
    cc->actions = malloc(cc->count * sizeof(action_t)); // TODO: free

    for (int i = 0; i < cc->count; i++)
    {
        const config_setting_t *action = config_setting_get_elem(setting, i);

        const char *action_name;
        if (!config_setting_lookup_string(action, "action", &action_name))
        {
            print_info("%s: element is missing the action\n", cfg_path);
            config_destroy(cfg);
            return 0;
        }
        cc->actions[i].name = (char *)action_name;

        if (!config_setting_lookup_int(action, "delay", &cc->actions[i].delay))
        {
            print_info("%s: element is missing the delay\n", cfg_path);
            config_destroy(cfg);
            return 0;
        }

        if (strcmp(action_name, "reboot") == 0)
        {
            // nothing to do
        }
        else if (strcmp(action_name, "service-restart") == 0)
        {
            if (!config_setting_lookup_string(action, "name", (const char **)&cc->actions[i].object))
            {
                print_info("%s: element is missing the name\n", cfg_path);
                config_destroy(cfg);
                return 0;
            }

            char *escaped_servicename = escape_servicename((char *)cc->actions[i].object);
            print_debug("Escaped \"%s\" to %s\n", (char *)cc->actions[i].object, escaped_servicename);
            cc->actions[i].object = escaped_servicename;
        }
        else if (strcmp(action_name, "command") == 0)
        {
            action_cmd_t *cmd = malloc(sizeof(action_cmd_t));

            if (!config_setting_lookup_string(action, "cmd", (const char **)&cmd->command))
            {
                print_info("%s: element is missing the cmd\n", cfg_path);
                config_destroy(cfg);
                return 0;
            }

            if (!config_setting_lookup_string(action, "user", (const char **)&cmd->user))
            {
                cmd->user = NULL;
            }

            cc->actions[i].object = cmd;
        }
        else
        {
            printf("%s: unknown element in configuration on line %d\n", cfg_path, action->line);
            config_destroy(cfg);
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
    if (!(c >= 48 && c <= 57) &&
        !(c >= 65 && c <= 90) && 
        !(c >= 97 && c <= 122))
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
            char buf[3];
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

int ends_with(char* str, char* end) {
    if (!str || !end) {
        return 0;
    }
    
    int len_str = strlen(str);
    int len_end = strlen(end);
    if (len_end > len_str)
        return 0;
    return strncmp(str + len_str - len_end, end, len_end) == 0;
}
