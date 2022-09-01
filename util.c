#include <arpa/inet.h>
#include <bits/types/struct_tm.h> 
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <unistd.h>

#include "util.h"
#include "actions.h"

#define PACKETSIZE  64
struct packet
{
    struct icmphdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

struct packet6
{
    struct icmp6_hdr hdr;
    char msg[PACKETSIZE-sizeof(struct icmp6_hdr)];
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
        return NULL;
    }

    int new_i = 0;
    for (int i = 0; i < len; i++)
    {
        char old = input_name[i];

        if (needs_escaping(old))
        {
            char buf[3];
            snprintf(buf, 3, "%x", old);

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

void get_current_time(char* str, const int str_len, const char* format, time_t* timestamp) {
    struct tm tm;
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);
    time_t t = now.tv_sec;
    
    localtime_r(&t, &tm);

    int ms = (int)(now.tv_nsec * 1e-6);
    char ms_str[4];
    snprintf(ms_str, 4, "%03d", ms);

    char* ms_replaced = str_replace(format, "%%ms", ms_str);

    strftime(str, str_len, ms_replaced, &tm);

    free(ms_replaced);

    if (timestamp != NULL) {
        *timestamp = t;
    }
}

void seconds_to_string(int seconds, char* dt_string) {
    int remainingSeconds = seconds;

    int days = remainingSeconds / (60*60*24);
    remainingSeconds = remainingSeconds % (60*60*24);
    
    int hours = remainingSeconds / (60*60);
    remainingSeconds = remainingSeconds % (60*60);
    
    int minutes = remainingSeconds / 60;
    int sec = remainingSeconds % 60;

    if (days != 0) {
        sprintf(dt_string, "%d days %02d:%02d:%02d", days, hours, minutes, sec);
    } else { // exclude days
        sprintf(dt_string, "%02d:%02d:%02d", hours, minutes, sec);
    }
}

char* insert_placeholders(const char* raw_message, 
                        const connectivity_check_t* check,
                        const char* datetime_format,
                        const double downtime,
                        const double uptime,
                        const int connected) {
    char* message = strdup(raw_message);

    const conn_state_t state = check->status;
    const struct timespec start_downtime = check->timestamp_first_failed;

    // replace %uptime
    if ((state & STATE_UP) || (state == STATE_DOWN_NEW)) {
        char dt_string[24];
        seconds_to_string((int)uptime, dt_string);

        const char* old = message;

        message = str_replace(message, "%uptime", dt_string);

        free((void*)old);
    }

    // replace %sdt
    if (state == STATE_UP_NEW || state & STATE_DOWN) {
        char str_time[32];
        struct tm time;
        localtime_r(&start_downtime.tv_sec, &time);

        strftime(str_time, 32, datetime_format, &time);

        int ms = (int)(start_downtime.tv_nsec * 1e-6);
        char ms_str[4];
        snprintf(ms_str, 4, "%03d", ms);

        char* ms_replaced = str_replace(str_time, "%ms", ms_str);

        const char* old = message;

        message = str_replace(message, "%sdt", ms_replaced);

        free((void *) ms_replaced);
        free((void*)old);
    }
    // replace %downtime
    if (state == STATE_UP_NEW || state & STATE_DOWN) {
        // difference string
        
        char dt_string[24];
        seconds_to_string((int)downtime, dt_string);
        
        const char* old = message;
        message = str_replace(message, "%downtime", dt_string);

        free((void*)old);
    }
    if (check->latency >= 0) {
        // latency +1 to avoid negative logarithms (are negative in ]1, 0[); 
        // +2 for null-term and one off by log10
        // +1 for period '.'
        // +2 for some precision
        int length = log10f(check->latency + 1) + 5;
        char* latency_str = malloc(length * sizeof(char));

        const char* old = message;

        snprintf(latency_str, length, "%1.2lf", check->latency * 1e3);
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
    time_t timestamp;
    get_current_time(str_now, 32, datetime_format, &timestamp);
    old = message;
    
    // replace %timestamp with the unix time
    char str_ts[16];
    sprintf(str_ts, "%ld", timestamp);
    message = str_replace(message, "%now", str_now);
    free((void*)old);
    old = message;
    
    message = str_replace(message, "%timestamp", str_ts);
    free((void*)old);

    return message;
}

double calculate_difference(struct timespec old, struct timespec new) {
    return (new.tv_sec - old.tv_sec) + (new.tv_nsec - old.tv_nsec) / 1.0e9;
}

int32_t calculate_difference_ms(struct timespec old, struct timespec new) {
    return (new.tv_sec - old.tv_sec) * 1000 + (new.tv_nsec - old.tv_nsec) / 1000000;
}

struct timespec timespec_add(const struct timespec t1, const struct timespec t2) {
    struct timespec result = t1;

    result.tv_sec += t2.tv_sec;
    result.tv_nsec += t2.tv_nsec;

    if (result.tv_nsec / (long)1e9 != 0) {
        result.tv_sec++;
        result.tv_nsec = result.tv_nsec % (int)1e9;
    }

    return result;
}

int to_sockaddr(const char* address, struct sockaddr_storage* socket_addr, sa_family_t* address_family) {
    struct sockaddr_in* ipv4_addr = (struct sockaddr_in*) socket_addr;
    int success = inet_pton(AF_INET, address, &ipv4_addr->sin_addr);

    *address_family = AF_INET;
    // might be ipv6
    if (!success) {
        success = inet_pton(AF_INET6, address, &((struct sockaddr_in6*) socket_addr)->sin6_addr);
        *address_family = AF_INET6;
    }

    return success;
}

int resolve_hostname(const logger_t* logger, const char *hostname, struct sockaddr_storage *socket_addr)
{
    struct addrinfo hint, *pai;
    int rv;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, NULL, &hint, &pai)) < 0)
    {
        sprint_error(logger, "[%s]: Unable to get address info: %s\n", hostname, gai_strerror(rv));
        return 0;
    }

    char addr[INET6_ADDRSTRLEN];
    struct sockaddr_in *p = (struct sockaddr_in *)pai->ai_addr;

    inet_ntop(AF_INET, &p->sin_addr, addr, INET_ADDRSTRLEN);

    if (pai->ai_family == AF_INET) {
        memcpy(socket_addr, &pai->ai_addr, sizeof(struct sockaddr_in));
    } else {
        memcpy(socket_addr, &pai->ai_addr, sizeof(struct sockaddr_in6));
    }

    freeaddrinfo(pai);
    return 1;
}

int create_socket(const logger_t* logger, const int address_family) {
    int sd;
    int proto = IPPROTO_ICMP;
    int domain = AF_INET;

    if (address_family == AF_INET6) {
        proto = IPPROTO_ICMPV6;
        domain = AF_INET6;
    }

    if ((sd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK, proto)) < 0)
    {
        sprint_error(logger, "Unable to open socket. %s\n", strerror(errno));
        return 0;
    }

    printf("created socket with domain %d\n", domain);

    return sd;
}

int create_epoll(const int fd) {
    // epoll on socket sd
    int epfd = epoll_create(1);

    struct epoll_event event;

    event.events = EPOLLIN;
    event.data.fd = fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);

    return epfd;
}

/*
 * Fills the message starting at point in the following format:
 *            `target IP`_`icmp_msgs_count`___..._
 */
void fill_message(char* point, const char* end, const char* address) {
    char* cptr = point;

    int addr_len = strlen(address);
        
    memcpy(cptr, address, addr_len);
    cptr += addr_len;
    *cptr = '_';
    cptr++;

    const int seq_str_len = 5; // maximum size of uint16_t as a string
    char seq_str[seq_str_len];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(seq_str, seq_str_len, "%d", icmp_msgs_count++);
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
    strncpy(cptr, seq_str, strlen(seq_str));
#pragma GCC diagnostic pop

    cptr += strlen(seq_str);

    for (; cptr < end - 1; cptr += 1) {
        *cptr = '_';
    }
    *cptr = 0;
}

char* create_packet(int family, const char* address) {
    char* packet = malloc(64 * sizeof(char));

    if (family == AF_INET) {
        struct packet* pptr = (struct packet*) packet;

        pptr->hdr.type = ICMP_ECHO;
        pptr->hdr.un.echo.sequence = icmp_msgs_count++;

        fill_message(pptr->msg, pptr->msg + 56, address);
    } else if (family == AF_INET6) {
        struct packet6* pptr = (struct packet6*) packet;

        pptr->hdr.icmp6_type = ICMP6_ECHO_REQUEST;

        fill_message(pptr->msg, pptr->msg + 56, address);
    } else {
        return NULL;
    }

    return packet;
}

int ping(const logger_t *logger,
         int* sd,
         int* epoll_fd,
         const char *address,
         double *latency_s,
         const double timeout_s)
{
    char* send_pckt;
    char* rcv_pckt = malloc(PACKETSIZE * sizeof(char));

    struct sockaddr_storage addr_ping;

    sa_family_t addr_family;
    
    memset(&addr_ping, 0, sizeof(addr_ping));
    if (!to_sockaddr(address, &addr_ping, &addr_family)) {
        // could be a hostname
        print_debug(logger, "Trying as a hostname: %s\n", address);
        if (!resolve_hostname(logger, address, &addr_ping)) {
            return (-1);
        }
    }

#if DEBUG
    close(*sd);
    close(*epoll_fd);
    *sd = create_socket(logger, addr_family);
    *epoll_fd = create_epoll(*sd);
#endif

    addr_ping.ss_family = addr_family;

    struct timespec sent_time;
    struct timespec rcvd_time;

    // construct packet and send
    memset(rcv_pckt, 0, PACKETSIZE);

    send_pckt = create_packet(addr_family, address);

    // Send the message
#if DEBUG
    sprint_debug(logger, "[%s]: Message sent: %s\n", address, send_pckt + 8);
#endif

    // Start the clock
    clock_gettime(CLOCK_REALTIME, &sent_time);

    int bytes_sent = 0;
    int tries = 0;

    if (*sd < 0 || *epoll_fd < 0) {
        *sd = create_socket(logger, addr_family);
        *epoll_fd = create_epoll(*sd);
    }

    do {
        if (addr_family == AF_INET) {
            print_debug(logger, "[%s]: ipv4 sendto\n", address);
            bytes_sent = sendto(*sd, send_pckt, PACKETSIZE, 0, (struct sockaddr *)&addr_ping, sizeof(struct sockaddr_in));
        } else {
            print_debug(logger, "[%s]: ipv6 sendto and packetsize %ld\n", address, sizeof(struct packet6));
            bytes_sent = sendto(*sd, send_pckt, PACKETSIZE, 0, (struct sockaddr*)&addr_ping, sizeof(struct sockaddr_in6));
        }

        if (tries >= 3) {
            struct stat info;

            int res = fstat(*sd, &info);

            sprint_error(logger, "[%s]: Unable to send on socket %d after %d tries: %s. fstat returned %d family: %d\n", address, *sd, tries, strerror(errno), res, addr_family);

            *sd = create_socket(logger, addr_family);
            *epoll_fd = create_epoll(*sd);

            return (-1);
        }

        if (bytes_sent < 0) { // error
            *sd = create_socket(logger, addr_family);
            *epoll_fd = create_epoll(*sd);

            sprint_debug(logger, "Created new socket for %s\n", address);
        } else { // this holds: bytes >= 0
            if (bytes_sent == 64) break;
            print_error(logger, "Only sent %d out of 64 bytes.\n", bytes_sent);

            return (-1);
        }
        tries++;
    } while(1);

    // receive
    struct epoll_event events[1];
    
    int num_ready = epoll_wait(*epoll_fd, events, 1, timeout_s * 1e3);

    if (num_ready < 0) {
        // Do not print if we got interrupted
        if (errno != EINTR) {
            print_debug(logger, "[%s]: Unable to receive: %s\n", address, strerror(errno));
        } else {
            // TODO: maybe return that an interrupt occured
        }

        *latency_s = -1.0;
        
        close(*sd);
        close(*epoll_fd);
        *sd = -1;
        *epoll_fd = -1;

        return 0;
    } else if (num_ready == 0) { // timeout
        clock_gettime(CLOCK_REALTIME, &rcvd_time);

        double diff = calculate_difference(sent_time, rcvd_time);

        print_debug(logger, "[%s]: Timeout after %1.2fms\n", address, diff * 1e3);

        *latency_s = -1.0;

        close(*sd);
        close(*epoll_fd);
        *sd = -1;
        *epoll_fd = -1;
        
        return 0;
    }

    if(events[0].events & EPOLLIN) {
#if DEBUG
        printf("Socket %d got some data\n", events[0].data.fd);
#endif
        size_t bytes_rcved = recv(*sd, rcv_pckt, PACKETSIZE, 0);
        
        if (bytes_rcved != 64) {
            printf("just received: %ld bytes: %s\n", bytes_rcved, (char *)rcv_pckt);

            return (-1);
        }
    }

    clock_gettime(CLOCK_REALTIME, &rcvd_time);

    // check if the message matches
    int is_exact_match = memcmp(send_pckt + 8, rcv_pckt + 8, 56) == 0;

    sprint_debug(logger, "[%s]: is_exact_match: %d\n", address, is_exact_match);

    if (is_exact_match) {
        *latency_s = calculate_difference(sent_time, rcvd_time);
    } else {
        *latency_s = -1.0;
        
        close(*sd);
        close(*epoll_fd);
        *sd = -1;
        *epoll_fd = -1;
    }

    return is_exact_match;
}
