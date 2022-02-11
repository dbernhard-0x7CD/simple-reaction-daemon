#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>

#include "srd.h"

#define CLOCKID CLOCK_REALTIME
#define SIG SIGRTMIN

char IP[] = "10.10.0.11";

char version[] = "0.0.1";

#define DEBUG 1

// frequency of connectivity checks in ms
#define FREQ 1000 * 60

#define MAX_MS_DISCONNECTED 4000

#define WAIT_FOR_REPLY_SECONDS 1

void signal_handler(int s)
{
    // TODO
}


int check_connectivity()
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

        int length = (int)((ceil(log10(WAIT_FOR_REPLY_SECONDS))+1)*sizeof(char));
        char str[length];
        sprintf(str, "%d", WAIT_FOR_REPLY_SECONDS);

        execlp("ping", "ping", 
                    "-c", "1",
                    "-w", str,
                    IP, (char *)0);
    }
    else if (f < 0)
    {
        printf("forking did not work\n");
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
}

int main()
{
    // data
    int running = 1;
    int ms_since_last_reply = 0;

    printf("Starting srd (Simple Reconnect Daemon) version ");
    printf(version);
    printf("\n");

    fflush(stdout);

    while (1)
    {
        // timer_settime(timerid, 0, &trigger, NULL);

        int connected = check_connectivity();
        if (connected == 1)
        {
#if DEBUG
            char *p;
            int len;
            time_t t = time(NULL);

            p = ctime(&t);
            len = strlen(p);

            printf("still reachable %.*s\n\n\n", len -1, p);
#endif
            ms_since_last_reply = 0;
        }
        else
        {
            printf("disconnected \n\n");
            ms_since_last_reply += FREQ;
        }

        if (ms_since_last_reply >= MAX_MS_DISCONNECTED)
        {
            printf("now do reconnect action\n");

            if (0 == restart_service()) {
                printf("dispatched command to restart\n");
            } else {
                printf("failed to dispatch\n");
                exit(1);
            }

            
        }

        fflush(stdout);

        usleep(FREQ * pow(10, 3));
    }

    return 0;
}

int restart_service()
{
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
        "/org/freedesktop/systemd1/unit/wg_2dquick_40wg0_2eservice",        /* object path */
        "org.freedesktop.systemd1.Unit",    /* interface name */
        "Restart",                          /* method name */
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

    printf("Queued service job as %s.\n", path);

finish:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
    sd_bus_unref(bus);

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
