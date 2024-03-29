#include <errno.h>
#include <systemd/sd-bus.h>
#include <pwd.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "srd.h"
#include "actions.h"
#include "perf_metric.h"
#include "printing.h"
#include "util.h"

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

int restart_service(const logger_t* logger, const char *name)
{
    print_debug(logger, "Restart service: %s\n", name);

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

    sprint_debug(logger, "Queued service job as %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r >= 0;
}

int run_command(const logger_t* logger, const action_cmd_t *cmd, const uint32_t timeout_ms, const char* actual_command)
{
    int stdin[2];

    if (pipe(stdin)) {
        sprint_error(logger, "Unable to create pipe to child\n");
        return 0;
    }

    int pid = fork();

    if (pid < 0)
    {
        sprint_error(logger, "Unable to fork. %s\n", strerror(errno));
        return 0;
    }
    else if (pid == 0)
    {
        // I am the child
        
        dup2(stdin[1], 1);
        
        // switch to user
        if (cmd->user != NULL)
        {
            struct passwd *a = getpwnam(cmd->user);
            uid_t uid = a->pw_uid;
            setuid(uid);
        }
       
        execl("/bin/sh", "sh", "-c", actual_command, NULL);

        sprint_error(logger, "execl failed.\n");
        return 0;
    }
    else
    {
        const size_t buf_size = 32;
        char buf[buf_size];

        // i'm not writing
        close(stdin[1]);

        int res;
        struct timespec start;
        clock_gettime(CLOCK, &start);
        struct timespec now;

        const uint32_t delta_ms = 1e5; // 100ms
        uint32_t diff_ms = 0;

        while ((res = waitpid(pid, NULL, WNOHANG)) == 0) {
            if (res < 0) {
                sprint_error(logger, "Unable to wait for pid %d: %s\n", pid, strerror(errno));

                return 0;
            }
            usleep(delta_ms); // sleep 100ms

            clock_gettime(CLOCK, &now);

            diff_ms = calculate_difference_ms(start, now);

            if (diff_ms >= timeout_ms) {
                sprint_error(logger, "Command %s took too long. Killing it and continuing.\n", actual_command);

                kill(pid, SIGTERM);
                waitpid(pid, NULL, WUNTRACED);
                return 0;
            }
        }

        int bytes_read;
        sprint_debug(logger, "Command output: ");
        while ((bytes_read = read(stdin[0], buf, buf_size - 1)) > 0)
        {
            buf[bytes_read] = '\0';
            sprint_debug_raw(logger, "%s", buf);
        }
        sprint_debug_raw(logger, "\n");

        close(stdin[0]);

        return res == pid;
    }

    return 1;
}

int log_to_file(const logger_t* logger, action_log_t* action_log, const char* actual_line)
{
    // check if the file is beeing created
    int is_new = 0;
    if (access(action_log->path, F_OK) != 0) {
        is_new = 1;
    }

    if (action_log->file == NULL) {
        sprint_debug(logger, "Opening file %s\n", action_log->path);
        action_log->file = fopen(action_log->path, "a");
    }

    if (action_log->file == NULL)
    {
        sprint_error(logger, "Unable to open file: %s (Reason: %s)\n", action_log->path, strerror(errno));
        return 0;
    }

    if (is_new && action_log->header != NULL) {
        fputs(action_log->header, action_log->file);
        fputs("\n", action_log->file);
    }

    fputs(actual_line, action_log->file);
    fputs("\n", action_log->file);

    // set permissions for the file when 
    // it's newly created
    if (is_new && action_log->username != NULL) {
        struct passwd *user_passwd = getpwnam(action_log->username);

        int r = chown(action_log->path, user_passwd->pw_uid, user_passwd->pw_gid);

        if (r < 0) {
            sprint_error(logger, "Unable to chown log file %s: %s\n", action_log->path, strerror(errno));
        }
    }
    fflush(action_log->file);

    return 1;
}

int influx_db(const logger_t* logger, action_influx_t* action, const char* actual_line) {
    ssize_t num_ready;
    ssize_t written_bytes;
    float timeout_left = action->timeout;

    MEASURE_INIT(measure);
    if (action->conn_socket <= 0) {
        // calculate address
        if (action->flags & FLAG_IS_HOSTNAME) {
            MEASURE_START(measure);

            if (!resolve_hostname(logger, action->host, action->sockaddr, timeout_left)) {
                sprint_error(logger, "Unable to get an IP for: %s\n", action->host);

                return 0;
            }
            char duration[32];
            MEASURE_GET_SINCE_STR(measure, duration)
            float resolve_duration = MEASURE_GET_SINCE(measure);

            timeout_left -= resolve_duration;
            if (timeout_left <= 0.0) {
                sprint_error(logger, "Timeout after %ds when resolving %s\n", action->timeout, action->host);
                return 0;
            }

            sprint_debug(logger, "Resolving hostname %s took: %s\n", action->host, duration);

            // set the port accordingly
            if (action->sockaddr->ss_family == AF_INET) {
                ((struct sockaddr_in*)action->sockaddr)->sin_port = htons(action->port);
            } else {
                ((struct sockaddr_in6*)action->sockaddr)->sin6_port = htons(action->port);
            }
        }

        action->conn_socket = socket(action->sockaddr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);

        if (action->conn_socket < 0) {
            sprint_error(logger, "[Influx]: Unable to create socket.\n");
            return 0;
        }
        action->conn_epoll_write_fd = epoll_create(1);
        action->conn_epoll_read_fd = epoll_create(1);

        // create epoll fd for writiting
        struct epoll_event event;
        event.events = EPOLLOUT;
        event.data.fd = action->conn_socket;

        epoll_ctl(action->conn_epoll_write_fd, EPOLL_CTL_ADD, action->conn_socket, &event);

        // create epoll fd for reading
        event.events = EPOLLIN | EPOLLET;
        event.data.fd = action->conn_socket;

        epoll_ctl(action->conn_epoll_read_fd, EPOLL_CTL_ADD, action->conn_socket, &event);

        // connect and measure time
        MEASURE_START(measure);
        int s;
        if (action->sockaddr->ss_family == AF_INET) {
            s = connect(action->conn_socket, (struct sockaddr *) action->sockaddr, sizeof(struct sockaddr_in));
        } else {
            s = connect(action->conn_socket, (struct sockaddr *) action->sockaddr, sizeof(struct sockaddr_in6));
        }
        
        // If s == 0, then we are successfully connected
        if (s == 0) {
            sprint_debug(logger, "[Influx]: Connected to %s:%d\n", action->host, action->port);
        } else if (s == -1 && errno == EINPROGRESS) {
            struct epoll_event events_write[1];
    
            // wait for maximum 10 seconds until we can write
            num_ready = epoll_wait(action->conn_epoll_write_fd, events_write, 1, timeout_left * 1e3);

            if (num_ready < 0) {
                sprint_error(logger, "[Influx]: Unable to connect to %s:%d: %s\n", action->host, action->port, strerror(errno));
                CLOSE(action);
                
                return 0;
            } else if (num_ready == 0) {
                char str_tmp[32];
                struct timespec now;
                clock_gettime(CLOCK, &now);
                format_time(datetime_ph, str_tmp, 32, &now);

                sprint_error(logger, "[Influx]: %s: Timeout after %ds when waiting for the connection to be established to %s:%d\n", str_tmp, action->timeout, action->host, action->port);
                
                CLOSE(action);

                return 0;
            } else {
                double took_s = MEASURE_GET_SINCE(measure);

                // Check socket
                int val;
                socklen_t len = sizeof(val);
                if ((s = getsockopt(action->conn_socket, SOL_SOCKET, SO_ERROR, &val, &len))) {
                    sprint_error(logger, "[Influx]: Unable to get status for socket: %d %s\n", s, strerror(s));

                    CLOSE(action);

                    return 0;
                }
                if (val != 0) {
                    sprint_error(logger, "Unable to connect to %s:%d: %s\n", action->host, action->port, strerror(val));

                    CLOSE(action);

                    return 0;
                }

                timeout_left -= took_s;
                if (timeout_left <= 0) {
                    sprint_error(logger, "[Influx]: Timeout after %ds when connecting to %s:%d\n", action->timeout, action->host, action->port);

                    CLOSE(action);
                    return 0; 
                }

                sprint_debug(logger, "[Influx]: Successfully connected to %s:%d in %1.3f seconds\n", action->host, action->port, took_s);
            }
        } else {
            sprint_error(logger, "[Influx]: Unable to connect to %s:%d:  %s\n", action->host, action->port, strerror(errno));

            CLOSE(action);
            return 0;
        }
    } // end of creating socket

    char header[256];
    int line_len = strlen(actual_line) + 1;
    char body[line_len];

    // create body
    snprintf(body, line_len, "%s\n", actual_line);

    // header
    snprintf(header, 256, "POST %s HTTP/1.1\r\n"
                          "Host: %s:%d\r\n"
                          "Content-Length: %zd\r\n"
                          "Authorization: %s\r\n\r\n",
                          action->endpoint, action->host, action->port, strlen(body), action->authorization);

    written_bytes = 0;
    // send the header
    do {
        MEASURE_START(measure);

        written_bytes = send(action->conn_socket, header, strlen(header), MSG_NOSIGNAL);

        if (written_bytes == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            struct epoll_event events_write[1];
            num_ready = epoll_wait(action->conn_epoll_write_fd, events_write, 1, timeout_left * 1e3);

            if (!running) {
                return 0;
            }

            if (num_ready <= 0) {
                sprint_error(logger, "[Influx]: Timeout after %ds while waiting for %s:%d.\n", action->timeout, action->host, action->port);

                CLOSE(action);
                return 0;
            }
            double took_s = MEASURE_GET_SINCE(measure);

            timeout_left -= took_s;
            if (timeout_left <= 0) {
                sprint_error(logger, "[Influx]: Timeout for %s:%d\n", action->host, action->port);
                return 0; 
            }
            continue;
        } else if (written_bytes == (ssize_t)strlen(header)) {
            break;
        }
        sprint_error(logger, "[Influx]: Unable to send to %s:%d %s\n", action->host, action->port, strerror(errno));
        CLOSE(action);
        return 0;
    } while (1);

    // send the body
    do {
        MEASURE_START(measure);
        written_bytes = send(action->conn_socket, body, strlen(body), MSG_NOSIGNAL);

        if (written_bytes == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            struct epoll_event events[1];

            // 2 seconds timeout for waiting until server is ready to receive data
            num_ready = epoll_wait(action->conn_epoll_write_fd, events, 1, timeout_left * 1e3);

            if (!running) {
                return 0;
            }

            if (num_ready < 0) {
                sprint_error(logger, "[Influx]: Error while waiting for %s:%d: %s.\n", action->host, action->port, strerror(errno));

                CLOSE(action);
                return 0;
            } else if (num_ready == 0) {
                sprint_error(logger, "[Influx]: Timeout while sending the body to %s:%d\n", action->host, action->port);

                CLOSE(action);

                return 0;
            }
            double took_s = MEASURE_GET_SINCE(measure);

            timeout_left -= took_s;
            if (timeout_left <= 0) {
                sprint_error(logger, "[Influx]: Timeout for %s:%d\n", action->host, action->port);
                return 0; 
            }
            continue;
        } else if (written_bytes == (ssize_t)strlen(body)) {
            break;
        }
        sprint_error(logger, "[Influx]: Unable to send body to %s:%d %s\n", action->host, action->port, strerror(errno));
        CLOSE(action);
        return 0;
    } while (1);

    // we only need to look at the start to see if we were successfull at
    // writing
    int read_bytes = 0;
    char answer[128];

    do {
        MEASURE_START(measure);
        read_bytes = read(action->conn_socket, answer, sizeof(answer));

        if (read_bytes == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            struct epoll_event events[1];

            // 2 seconds timeout for processing
            num_ready = epoll_wait(action->conn_epoll_read_fd, events, 1, timeout_left * 1e3);

            if (!running) {
                return 0;
            }

            if (num_ready < 0) {
                sprint_error(logger, "[Influx]: Error while waiting for an answer %s:%d: %s.\n", action->host, action->port, strerror(errno));

                CLOSE(action);
                return 0;
            } else if (num_ready == 0) {
                sprint_error(logger, "[Influx]: Timeout when waiting for an answer from %s:%d\n", action->host, action->port);

                CLOSE(action);

                return 0;
            }
            double took_s = MEASURE_GET_SINCE(measure);

            timeout_left -= took_s;
            
            continue;
        } else if (read_bytes > 22) {
            break;
        }

        sprint_error(logger, "[Influx]: Unable to receive answer from %s:%d %s\n", action->host, action->port, strerror(errno));
        CLOSE(action);
        return 0;
    } while (1);

    answer[read_bytes] = '\0';

    // check if starts with start_success
    const char* start_success = "HTTP/1.1 204 No Content";
    if (strncmp(answer, start_success, 23) == 0) {
        double influx_time_s = action->timeout * 1.0 - timeout_left;

        sprint_debug(logger, "[Influx]: Success. Took %1.3f seconds\n", influx_time_s);
        return 1;
    }

    sprint_error(logger, "[Influx] Failed wo send to influxdb. Received: %s\n", answer);
    
    CLOSE(action);

    return 0;
}

int influx(const logger_t* logger, action_influx_t* action, const char* actual_line) {
    int status = influx_db(logger, action, actual_line);

    // Return if successfull
    if (status) return 1;

    // Return 0 if no backup path is defined
    if (action->backup_path == NULL) return 0;

    // check if the file is beeing created
    int is_new = 0;
    if (access(action->backup_path, F_OK) != 0) {
        is_new = 1;
    }

    FILE *f = fopen(action->backup_path, "a");

    if (f == NULL)
    {
        sprint_error(logger, "Unable to open file: %s (Reason: %s)\n", action->backup_path, strerror(errno));
        return 0;
    }

    fputs(actual_line, f);
    fputs("\n", f);

    // set permissions for the file when 
    // it's newly created
    if (is_new && action->backup_username != NULL) {
        struct passwd *user_passwd = getpwnam(action->backup_username);

        int r = chown(action->backup_path, user_passwd->pw_uid, user_passwd->pw_gid);

        if (r < 0) {
            sprint_error(logger, "Unable to chown log file %s: %s\n", action->backup_path, strerror(errno));
        }
    }

    fclose(f);

    sprint_error(logger, "Succesfully written to backup file: %s\n", action->backup_path);

    return 1;
}
