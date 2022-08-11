#include <errno.h>
#include <systemd/sd-bus.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#include "actions.h"
#include "printing.h"

int restart_system(const logger_t* logger)
{
#ifdef DEBUG
    return 1; // success
#endif
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *msg = NULL;
    sd_bus *bus = NULL;
    const char *path;
    int r;

    /* Connect to the system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0)
    {
        sprint_error(logger, "Failed to connect to system bus: %s\n", strerror(-r));
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
        print_error(logger, "Failed to issue method call: %s\n", error.message);
        goto finish;
    }

    /* Parse the response message */
    r = sd_bus_message_read(msg, "o", &path);
    if (r < 0)
    {
        sprint_error(logger, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(msg);
    sd_bus_unref(bus);

    return r >= 0;
}

int restart_service(const logger_t* logger, const char *name, const char *ip)
{
    print_debug(logger, "[%s]: Restart service %s\n", ip, name);

    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message *m = NULL;
    sd_bus *bus = NULL;
    const char *path;
    int r;

    /* Connect to the system bus */
    r = sd_bus_open_system(&bus);
    if (r < 0)
    {
        sprint_error(logger, "Failed to connect to system bus: %s\n", strerror(-r));
        goto finish;
    }
    char *prefix = "/org/freedesktop/systemd1/unit/";
    int prefix_len = strlen(prefix);
    char *service_name = malloc(prefix_len + strlen(name) + 1);

    strcpy(service_name, prefix);
    strcpy(service_name + prefix_len, name);

    sprint_debug(logger, "Object path: %s\n", service_name);

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
        sprint_error(logger, "Failed to issue method call: %s\n", error.message);
        free(service_name);
        goto finish;
    }
    free(service_name);

    /* Parse the response message */
    r = sd_bus_message_read(m, "o", &path);
    if (r < 0)
    {
        sprint_error(logger, "Failed to parse response message: %s\n", strerror(-r));
        goto finish;
    }

    sprint_debug(logger, "[%s]: Queued service job as %s.\n", ip, path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r >= 0;
}

int run_command(const logger_t* logger, const action_cmd_t *cmd)
{
    FILE *fp;
    char buf[1024];

    int pid = fork();

    if (pid < 0)
    {
        sprint_error(logger, "Unable to fork.\n");
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
            sprint_error(logger, "Failed to run command\n");
            return EXIT_FAILURE;
        }

        while (fgets(buf, sizeof(buf), fp) != NULL)
        {
            sprint_info(logger, "Command output: %s", buf);
        }

        pclose(fp);
        exit(0);
    }
    else
    {
        // await child
        waitpid(pid, NULL, WUNTRACED);
    }

    return 1;
}

int log_to_file(const logger_t* logger, const char *path, const char *message, const char* username)
{
    FILE *file;

    // check if the file is beeing created
    int is_new = 0;
    if (access(path, F_OK) != 0) {
        is_new = 1;
    }

    file = fopen(path, "a");

    if (file == NULL)
    {
        print_error(logger, "Unable to open file: %s (Reason: %s)\n", path, strerror(errno));
        return 0;
    }

    fputs(message, file);
    fputs("\n", file);

    int ret_code = fclose(file) == 0;

    // set permissions for the file when 
    // it's newly created
    if (is_new && username != NULL) {
        struct passwd *user_passwd = getpwnam(username);

        int r = chown(path, user_passwd->pw_uid, user_passwd->pw_gid);

        if (r < 0) {
            sprint_error(logger, "Unable to chown log file %s: %s\n", path, strerror(errno));
        }
    }

    return ret_code;
}
