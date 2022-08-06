#include <arpa/inet.h>
#include <bits/types/struct_tm.h> 
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "util.h"


#define PACKETSIZE  64
struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

_Atomic(unsigned int) icmp_msgs_count = 1; // sequence number

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
    escaped_str[new_len - 1] = '\0';

    return escaped_str;
}

int ends_with(char *str, char *end)
{
    if (!str || !end)
    {
        return 0;
    }

    int len_str = strlen(str);
    int len_end = strlen(end);
    if (len_end > len_str)
        return 0;
    return strncmp(str + len_str - len_end, end, len_end) == 0;
}

// this is from: https://gist.github.com/bg5sbk/11058000
char *str_replace(const char *string, const char *substr, const char *replacement)
{
    char *tok = NULL;
    char *newstr = NULL;
    char *oldstr = NULL;
    int oldstr_len = 0;
    int substr_len = 0;
    int replacement_len = 0;

    newstr = strdup(string);
    substr_len = strlen(substr);
    replacement_len = strlen(replacement);

    if (substr == NULL || replacement == NULL)
    {
        return newstr;
    }

    while ((tok = strstr(newstr, substr)))
    {
        oldstr = newstr;
        oldstr_len = strlen(oldstr);
        newstr = (char *)malloc(sizeof(char) * (oldstr_len - substr_len + replacement_len + 1));

        if (newstr == NULL)
        {
            free(oldstr);
            return NULL;
        }

        memcpy(newstr, oldstr, tok - oldstr);
        memcpy(newstr + (tok - oldstr), replacement, replacement_len);
        memcpy(newstr + (tok - oldstr) + replacement_len, tok + substr_len, oldstr_len - substr_len - (tok - oldstr));
        memset(newstr + oldstr_len - substr_len + replacement_len, 0, 1);

        free(oldstr);
    }

    return newstr;
}

char *get_default_gw()
{
    long dest;
    long gw;
    char iface[IF_NAMESIZE];
    char buffer[1024];
    FILE *file;

    file = fopen("/proc/net/route", "r");
    if (!file)
    {
        printf("Unable to access /proc/net/route to get the default gateway\n");
        return 0;
    }

    while (fgets(buffer, sizeof(buffer), file))
    {
        if (sscanf(buffer, "%s %lx %lx", iface, &dest, &gw) == 3)
        {
            if (dest == 0)
            {
                int size = INET_ADDRSTRLEN * sizeof(char);
                char *str = malloc(size);

                if (inet_ntop(AF_INET, &gw, str, INET_ADDRSTRLEN))
                {
                    fclose(file);
                    return str;
                }

                printf("Unable to get the IP of the gateway: %s\n", strerror(errno));

                fclose(file);
                return NULL;
            }
        }
    }
    if (file)
    {
        fclose(file);
    }

    printf("Did not find the default route\n");
    return NULL;
}

void get_current_time(char* str, const int n, const char* format) {
    struct tm tm;
    time_t t = time(NULL);
    
    localtime_r(&t, &tm);

    strftime(str, n, format, &tm);
}

char* insert_placeholders(const char* raw_message, 
                        const connectivity_check_t* check,
                        const conn_state_t state,
                        const struct timespec previous_last_reply,
                        const char* datetime_format,
                        const double diff,
                        const int connected) {
    char* message = strdup(raw_message);

    // replace %sdt
    if (state == STATE_UP_NEW) {
        char str_time[32];
        struct tm time;
        localtime_r(&previous_last_reply.tv_sec, &time);

        strftime(str_time, 32, datetime_format, &time);

        const char* old = message;

        message = str_replace(message, "%sdt", str_time);

        free((void*)old);
    }
    // replace %downtime
    if (state == STATE_UP_NEW || state & STATE_DOWN) {
        // difference string
        int remainingSeconds = (int) diff;

        int days = remainingSeconds / (60*60*24);
        remainingSeconds = remainingSeconds % (60*60*24);
        
        int hours = remainingSeconds / (60*60);
        remainingSeconds = remainingSeconds % (60*60);
        
        int minutes = remainingSeconds / 60;
        int seconds = remainingSeconds % 60;

        char dt_string[24];
        if (days != 0) {
            sprintf(dt_string, "%d days %02d:%02d:%02d", days, hours, minutes, seconds);
        } else { // exclude days
            sprintf(dt_string, "%02d:%02d:%02d", hours, minutes, seconds);
        }
        
        const char* old = message;
        message = str_replace(message, "%downtime", dt_string);

        free((void*)old);
    }
    if (check->latency >= 0) {
        // latency +1 to avoid negative logarithms; +2 for null-term and one off by log10
        int length = log10f(check->latency + 1) + 2;
        char* latency_str = malloc(length * sizeof(char));

        const char* old = message;

        snprintf(latency_str, length, "%1.0lf", check->latency);
        message = str_replace(message, "%lat_ms", latency_str);

        free(latency_str);
        free((char *)old);
    } else {
        const char* old = message;
        message = str_replace(message, "%lat_ms", "-1.0");
        free((char *)old);
    }

    // replace %status
    const char* old = message;
    if (connected) {
        message = str_replace(message, "%status", "success");
    } else {
        message = str_replace(message, "%status", "failed");
    }
    free((char *) old);

    // replace %now
    char str_now[32];
    get_current_time(str_now, 32, datetime_format);
    old = message;
    message = str_replace(message, "%now", str_now);
    free((void*)old);

    return message;
}

double calculate_difference(struct timespec old, struct timespec new) {
    return (new.tv_sec - old.tv_sec) + (new.tv_nsec - old.tv_nsec) / 1.0e9;
}

int to_sockaddr(const char* address, struct sockaddr_in* socket_addr) {
    return inet_pton(AF_INET, address, &(socket_addr->sin_addr));
}

int ping(const logger_t *logger,
         const char *address,
         double *latency_s,
         const double timeout_s)
{
    const int ttl = 255;
    
    struct packet pckt;
    struct sockaddr_in r_addr;
    struct sockaddr_in addr_ping;

    unsigned int i;
    int sd;
    
    memset(&addr_ping, 0, sizeof(addr_ping));
    if (!to_sockaddr(address, &addr_ping)) {
        // could be a hostname
        print_error(logger, "This address may be malformed: %s\n", address);
        return 0;
    }
    addr_ping.sin_port = 0;
    addr_ping.sin_family = AF_INET;

    sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sd < 0)
    {
        sprint_error(logger, "[%s]: Unable to open socket. %s\n", address, strerror(errno));
        return 0;
    }
    if (setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    {
        sprint_error(logger, "Set TTL option\n");
        close(sd);
        return 0;
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
    {
        sprint_error(logger, "Request nonblocking I/O\n");
        close(sd);
        return 0;
    }

    struct timespec sent_time;
    struct timespec rcvd_time;

    // construct packet and send
    bzero(&pckt, sizeof(pckt));
    unsigned char *pckt_ptr = (unsigned char *)&pckt;

    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.sequence = icmp_msgs_count++;

    // unsigned int msg_sent_size = sizeof(pckt.msg);
    // sprint_debug(logger, "[%s]: Message size: %d\n", address, msg_sent_size);

    // fill the message
    for (i = 0; i < sizeof(pckt.msg) - 1; i++)
    {
        pckt.msg[i] = '_';
    }
    int addr_len = strlen(address);
    strncpy(&pckt.msg[0], address, addr_len);

    const int seq_str_len = (int)(log10f(1.0*pckt.hdr.un.echo.sequence)) + 1;
    char* seq_str = malloc(seq_str_len * sizeof(char));

    sprintf(seq_str, "%d", pckt.hdr.un.echo.sequence);
    // insert sequence number
    strncpy(&pckt.msg[addr_len + 1], seq_str, seq_str_len);
    free(seq_str);

    pckt.msg[i] = 0; // terminator

#if DEBUG
    sprint_debug(logger, "[%s]: Message sent: %s\n", address, pckt.msg);
#endif

    // print entire packet
#if DEBUG
    for (i = 0; i < PACKETSIZE; i++)
    {
        sprint_debug(logger, "packet at %d: %d\n", i, pckt_ptr[i]);
    }
#endif

    // Start the clock
    clock_gettime(CLOCK_REALTIME, &sent_time);

    int bytes;
    if ((bytes = sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&addr_ping, sizeof(addr_ping))) <= 0)
    {
        sprint_error(logger, "Unable to send\n");
        close(sd);
        return 0;
    }

#if DEBUG
    sprint_debug(logger, "[%s]: Sent %d bytes with echo.id %d and SEQ %d\n", address, bytes, pckt.hdr.un.echo.id, pckt.hdr.un.echo.sequence);
#endif

    // receive
    // +20 as another header is included
    int rcv_len = 64;
    unsigned char *rcv_pckt = (unsigned char *)malloc(rcv_len);
    unsigned int len_new = sizeof(r_addr);

    // partial rcvs
    int rcv = 0;
    int bytes_rcved = 0;
    const int WAIT_TIME_US = 5e2; // 50 µs
    double ms_waited = 0;

    do
    {
        rcv = recvfrom(sd, rcv_pckt, rcv_len - bytes_rcved, 0, &r_addr, &len_new);
        if (rcv < 0) {
            usleep(WAIT_TIME_US);
        }
        if (rcv >= 0)
        {
            bytes_rcved += rcv;
        }

        ms_waited += WAIT_TIME_US * 1e-3;
        usleep(WAIT_TIME_US);

        if (ms_waited > timeout_s * 1e3)
        {
            print_debug(logger, "Timeout\n");
            close(sd);
            return 0;
        }
    } while (bytes_rcved < rcv_len);

    clock_gettime(CLOCK_REALTIME, &rcvd_time);

    struct packet *rcv_pckt2 = (struct packet *)rcv_pckt;

    sprint_debug(logger, "[%s]: Read %d bytes with SEQ %d\n", address, bytes_rcved, rcv_pckt2->hdr.un.echo.sequence);

#if DEBUG
    // print entire packet
    for (i = 0; i < PACKETSIZE + 20; i++)
    {
        printf("rcved message:[%d]: %d\n", i, rcv_pckt[i]);
    }
#endif
    sprint_debug(logger, "[%s]: Message received: %s\n", address, rcv_pckt2->msg);

    // check if the message matches
    int mem_diff = memcmp(&pckt_ptr[8], &rcv_pckt[8], 56);

    sprint_debug(logger, "[%s]: difference: %d\n", address, mem_diff);

    int success = mem_diff == 0;

    if (success)
    {
        *latency_s = calculate_difference(sent_time, rcvd_time);
    }
    else
    {
        *latency_s = -1.0;
    }

    // free
    free(rcv_pckt);

    close(sd);

    return success;
}
