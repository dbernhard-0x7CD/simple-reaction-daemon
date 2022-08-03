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

struct protoent *proto = NULL;
unsigned int icmp_msgs_count = 1; // sequence number

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
        char* latency_str = malloc((log10f(check->latency) + 1) * sizeof(char));

        const char* old = message;

        sprintf(latency_str, "%1.0lf", check->latency);
        message = str_replace(message, "%lat_ms", latency_str);

        free(latency_str);
        free((char *)old);
    } else {
        message = str_replace(message, "%lat_ms", "-1.0");
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

unsigned short complement_checksum(const void *buffer, int len)
{
    const unsigned short *ptr = buffer;
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2) {
        sum += *ptr++;
    }
    if (len == 1) {
        sum += *(unsigned char *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    
    sum += (sum >> 16);
    
    return ~sum;
}

int ping(const logger_t *logger,
        const char *address,
        double *latency_s,
        const double timeout_s)
{
    const int ttl = 255;

    pid_t tid = pthread_self();

    printf("I'm pinging %s with tid %d\n", address, (char) tid);
    
    struct packet pckt;
    struct sockaddr_in r_addr;
    struct hostent *hname;
    struct sockaddr_in addr_ping;

    size_t i;
    int sd;
    int pid = getpid();
    
    unsigned int ms_waited = 0;

    proto = getprotobyname("ICMP");
    hname = gethostbyname(address);
    memset(&addr_ping, 0, sizeof(addr_ping));
    addr_ping.sin_family = hname->h_addrtype;
    addr_ping.sin_port = 0;
    addr_ping.sin_addr.s_addr = *(long *)hname->h_addr;

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (sd < 0)
    {
        sprint_error(logger, "Unable to open socket. %s\n", strerror(errno));
        return 0;
    }
    if (setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0)
    {
        sprint_error(logger, "Set TTL option\n");
        return 0;
    }
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
    {
        sprint_error(logger, "Request nonblocking I/O\n");
        return 0;
    }

    struct timespec sent_time;
    struct timespec rcvd_time;

    // construct packet and send
    bzero(&pckt, sizeof(pckt));
    unsigned char* pckt_ptr = (unsigned char*)&pckt;

    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.un.echo.id = pid;
    unsigned int address_str_len = strlen(address);
    
    size_t msg_sent_size = sizeof(pckt.msg);
    sprint_debug(logger, "Message size: %lu\n", msg_sent_size);

    // fill the message
    for (i = 0; i < sizeof(pckt.msg) - 1; i++) {
        if (i < address_str_len) {
            pckt.msg[i] = address[i];
        } else {
            pckt.msg[i] = i - address_str_len + '0';
        }
    }
    pckt.msg[i] = 0; // terminator
    pckt.hdr.un.echo.sequence = icmp_msgs_count++;
    pckt.hdr.checksum = complement_checksum(&pckt, sizeof(pckt));

    // print entire packet
#if DEBUG
    for (i = 0; i < PACKETSIZE; i++) {
        sprint_debug(logger, "packet at %ld: %d\n", i, pckt_ptr[i]);
    }
#endif

    // sprint_debug(logger, "Sending packet with echo.id: %d, \n", pckt.hdr.un.echo.id);

    // Start the clock
    clock_gettime(CLOCK_REALTIME, &sent_time);
    
    int bytes;
    if ((bytes = sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&addr_ping, sizeof(addr_ping))) <= 0) {
        sprint_error(logger, "Unable to send\n");
        return 0;
    }
    sprint_debug(logger, "Sent %d bytes\n", bytes);

    // receive
    // +20 as another header is included
    int rcv_len = 64 + 20;
    unsigned char* rcv_pckt = (unsigned char*)malloc(rcv_len);
    unsigned int len_new = sizeof(r_addr);

    // partial rcvs
    int rcv = 0;
    int bytes_rcved = 0;
    do
    {
        rcv = recvfrom(sd, rcv_pckt, rcv_len, 0, &r_addr, &len_new);
        if (rcv >= 0) {
            bytes_rcved += rcv;
        }

        ms_waited++;
        // print_debug(logger, "waiting 1ms\n");
        usleep(1e3); // 1ms

        if (ms_waited > timeout_s * 1e3) {
            print_debug(logger, "Timeout\n");
            return 0;
        }
    } while (bytes_rcved < rcv_len);

    clock_gettime(CLOCK_REALTIME, &rcvd_time);

    sprint_debug(logger, "Read %d bytes\n", bytes_rcved);

#if DEBUG
    // print entire packet
    for (i = 0; i < PACKETSIZE + 20; i++) {
        printf("rcved message:[%ld]: %d\n", i, rcv_pckt[i]);
    }
#endif

    // check if correct message
    int mem_diff = memcmp(&pckt_ptr[8], &rcv_pckt[28], 56);

    sprint_debug(logger, "difference: %d\n", mem_diff);

    *latency_s = calculate_difference(sent_time, rcvd_time);
    return mem_diff == 0;
}
