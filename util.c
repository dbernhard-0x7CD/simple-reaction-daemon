#include <arpa/inet.h>
#include <bits/types/struct_tm.h> 
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
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
#include "perf_metric.h"
#include "srd.h"

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

char *escape_servicename(const char *input_name)
{
    // count characters which need escaping
    const char *start = input_name;
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

int ends_with(const char *str, const char *end)
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

void format_time(const placeholder_t* format, char* str_time, const size_t len, const struct timespec* time) {
    struct tm tm;
    
    localtime_r(&time->tv_sec, &tm);

    if (format->info & FLAG_CONTAINS_MS) {
        char* ms_replaced = (char *)format->raw_message;

        int ms = (int)(time->tv_nsec * 1e-6);
        char ms_str[4];
        snprintf(ms_str, 4, "%03d", ms);

        ms_replaced = str_replace(format->raw_message, "%%ms", ms_str);
        
        strftime(str_time, len, ms_replaced, &tm);

        free(ms_replaced);
    } else {
        strftime(str_time, len, format->raw_message, &tm);
    }
}

void seconds_to_string(const int seconds, char* dt_string) {
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

void ms_to_string(const int ms, char* dt_string) {
    int remainingSeconds = ms / 1000;

    int days = remainingSeconds / (60*60*24);
    remainingSeconds = remainingSeconds % (60*60*24);
    
    int hours = remainingSeconds / (60*60);
    remainingSeconds = remainingSeconds % (60*60);
    
    int minutes = remainingSeconds / 60;
    int sec = remainingSeconds % 60;

    int ms_remaining = ms % 1000;

    if (days != 0) {
        sprintf(dt_string, "%d days %02d:%02d:%02d.%03d", days, hours, minutes, sec, ms_remaining);
    } else { // exclude days
        sprintf(dt_string, "%02d:%02d:%02d.%03d", hours, minutes, sec, ms_remaining);
    }
}

replacement_info_t get_replacements(const char* message) {
    replacement_info_t info = 0;

    if (strstr(message, "%uptime")) {
        info |= FLAG_CONTAINS_UPTIME;
    }
    if (strstr(message, "%sdt")) {
        info |= FLAG_CONTAINS_SDT;
    }
    if (strstr(message, "%sut")) {
        info |= FLAG_CONTAINS_SUT;
    }
    if (strstr(message, "%downtime")) {
        info |= FLAG_CONTAINS_DOWNTIME;
    }
    if (strstr(message, "%lat_ms")) {
        info |= FLAG_CONTAINS_LAT_MS;
    }
    if (strstr(message, "%status")) {
        info |= FLAG_CONTAINS_STATUS;
    }
    if (strstr(message, "%now")) {
        info |= FLAG_CONTAINS_NOW;
    }
    if (strstr(message, "%timestamp")) {
        info |= FLAG_CONTAINS_TIMESTAMP;
    }

    return info;
}


char* insert_placeholders(const placeholder_t* placeholder, 
                        const connectivity_check_t* check,
                        const double downtime,
                        const double uptime,
                        const int connected) {
    char* message = strdup(placeholder->raw_message);
    replacement_info_t info = placeholder->info;

    char temp_str[48];

    // replace %uptime
    if (info & FLAG_CONTAINS_UPTIME) {
        seconds_to_string((int)uptime, temp_str);

        const char* old = message;
        message = str_replace(message, "%uptime", temp_str);
        free((void*)old);
    }

    // replace %sdt
    if (info & FLAG_CONTAINS_SDT) {
        format_time(datetime_ph, temp_str, 48, &check->timestamp_first_failed);

        const char* old = message;
        message = str_replace(message, "%sdt", temp_str);
        free((void*)old);
    }

    // replace %sut
    if (info & FLAG_CONTAINS_SUT) {
        format_time(datetime_ph, temp_str, 48, &check->timestamp_first_reply);

        const char* old = message;
        message = str_replace(message, "%sut", temp_str);
        free((void*)old);
    }

    // replace %downtime
    if (info & FLAG_CONTAINS_DOWNTIME) {
        seconds_to_string((int)downtime, temp_str);
        
        const char* old = message;
        message = str_replace(message, "%downtime", temp_str);

        free((void*)old);
    }

    // replace %lat_ms
    if (info & FLAG_CONTAINS_LAT_MS) {
        if (check->latency >= 0) {
            // latency +1 to avoid negative logarithms (are negative in ]1, 0[); 
            // +2 for null-term and one off by log10
            // +1 for period '.'
            // +2 for some precision
            int length = (int)log10f(check->latency * 1e3 + 1.0) + 5;

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
    }

    // replace %status
    if (info & FLAG_CONTAINS_STATUS) {
        const char* old = message;
        if (connected) {
            message = str_replace(message, "%status", "success");
        } else {
            message = str_replace(message, "%status", "failed");
        }
        free((char *) old);
    }

    // replace %now
    if (info & FLAG_CONTAINS_NOW) {
        const char* old = message;

        struct timespec now;
        clock_gettime(CLOCK, &now);

        format_time(datetime_ph, temp_str, 48, &now);
        message = str_replace(message, "%now", temp_str);

        free((char *) old);
    }
    
    // replace %timestamp with the unix time
    if (info & FLAG_CONTAINS_TIMESTAMP) {
        const char* old = message;
        time_t timestamp;
        time(&timestamp);
        char str_ts[16];
        sprintf(str_ts, "%ld", timestamp);
        
        message = str_replace(message, "%timestamp", str_ts);

        free((void*)old);
    }
    
    return message;
}

double calculate_difference(const struct timespec old, const struct timespec new) {
    return (new.tv_sec - old.tv_sec) + (new.tv_nsec - old.tv_nsec) / 1.0e9;
}

int32_t calculate_difference_ms(const struct timespec old, const struct timespec new) {
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

int to_sockaddr(const char* address, struct sockaddr_storage* socket_addr) {
    struct sockaddr_in* ipv4_addr = (struct sockaddr_in*) socket_addr;
    int success = inet_pton(AF_INET, address, &ipv4_addr->sin_addr);

    // might be ipv6
    if (!success) {
        success = inet_pton(AF_INET6, address, &((struct sockaddr_in6*) socket_addr)->sin6_addr);
        if (success) {
            socket_addr->ss_family = AF_INET6;
        }
    } else {
        // |> IPv4 worked
        socket_addr->ss_family = AF_INET;
    }

    return success;
}

int resolve_hostname(const logger_t* logger, const char *hostname, struct sockaddr_storage *socket_addr, float timeout_s)
{
    float nsec = timeout_s - (float)((int) timeout_s);
    const struct timespec timeout = { .tv_nsec = (int)(nsec * 1e9), .tv_sec = (int) timeout_s };
    int rv;

    struct gaicb *reqs;

    reqs = calloc(1, sizeof(struct gaicb));
    reqs->ar_name = hostname;

	rv = getaddrinfo_a(GAI_NOWAIT, &reqs, 1, NULL);
	if (rv != 0) {
		sprint_error(logger, "Unable to to get address for %s: %s", hostname, gai_strerror(rv));

        if (reqs->ar_request) {
            freeaddrinfo((struct addrinfo*) reqs->ar_request);
        }
        if (reqs->ar_result) {
            freeaddrinfo(reqs->ar_result);
        }
        free(reqs);

		return 0;
	}

	rv = gai_suspend((const struct gaicb * const*)&reqs, 1, &timeout);

    if (rv == 0 || rv == EAI_ALLDONE || rv == EAI_INTR) {
        struct addrinfo* ainfo = reqs->ar_result;

        if ((rv = gai_error(reqs)) != 0) {
            sprint_error(logger, "Unable to resolve hostname %s: %s\n", hostname, gai_strerror(rv))

            freeaddrinfo((struct addrinfo *) reqs->ar_request);
            free(reqs);

            return 0;
        }

        // write resolved address to socket_addr
        if (ainfo->ai_family == AF_INET) {
            memcpy(socket_addr, reqs->ar_result->ai_addr, sizeof(struct sockaddr_in));
        } else {
            memcpy(socket_addr, reqs->ar_result->ai_addr, sizeof(struct sockaddr_in6));
        }

        socket_addr->ss_family = ainfo->ai_family;

        if (gai_cancel(reqs) == EAI_NOTCANCELED) {
            sprint_info(logger, "Leaking memory\n");

            return 1;
    	}

        if ((struct addrinfo *) reqs->ar_request) {
            free((struct addrinfo *) reqs->ar_request);
        }
        if (reqs->ar_result) {
            freeaddrinfo(reqs->ar_result);
        }
        free(reqs);

        return 1;
    } else if (rv == EAI_AGAIN) {
        sprint_error(logger, "Timeout when resolving %s\n", hostname);

        freeaddrinfo((struct addrinfo *) reqs->ar_request);
        free(reqs);

        return 0;
    }

    sprint_error(logger, "Unable to resolve hostname %s: %s\n", hostname, gai_strerror(rv))

    freeaddrinfo((struct addrinfo *) reqs->ar_request);
    free(reqs);

    return 0;
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

    // sprint_debug(logger, "Created socket with family: %d\n", address_family);

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

    const size_t seq_str_len = 5; // maximum size of uint16_t as a string
    char seq_str[seq_str_len];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
    snprintf(seq_str, seq_str_len, "%d", icmp_msgs_count++);
#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wstringop-overflow"
    strncpy(cptr, seq_str, strlen(seq_str));
#pragma GCC diagnostic pop

    cptr += strlen(seq_str);

    for (; cptr < end - 1; cptr += 1) {
        *cptr = '_';
    }
    *cptr = 0;
}

void initialize_packet(char* packet_base, int family, const char* address) {
    memset(packet_base, 0, 64 * sizeof(char));

    if (family == AF_INET) {
        struct packet* pptr = (struct packet*) packet_base;

        pptr->hdr.type = ICMP_ECHO;
        pptr->hdr.un.echo.sequence = icmp_msgs_count++;

        fill_message(pptr->msg, pptr->msg + 56, address);
    } else if (family == AF_INET6) {
        struct packet6* pptr = (struct packet6*) packet_base;

        pptr->hdr.icmp6_type = ICMP6_ECHO_REQUEST;

        fill_message(pptr->msg, pptr->msg + 56, address);
    } 
}

int ping(const logger_t *logger,
         connectivity_check_t* check)
{
    int flags = MSG_NOSIGNAL;

    // resolve hostname each ping
    if (check->flags & FLAG_IS_HOSTNAME) {
        // could be a hostname
        sprint_debug(logger, "Trying as a hostname: %s\n", check->address);

        MEASURE_INIT(resolve_dns);
        MEASURE_START(resolve_dns);

        if (!resolve_hostname(logger, check->address, check->sockaddr, DNS_RESOLVE_TIMEOUT)) {
            return (-1);
        }
        char duration[32];
        MEASURE_GET_SINCE_STR(resolve_dns, duration);

        sprint_debug(logger, "Resolving hostname %s took: %s\n", check->address, duration);
    }

#if DEBUG
    if (check->socket > 0) {
        close(check->socket);
    }
    if (check->epoll_fd > 0) {
        close(check->epoll_fd);
    }
    check->socket = create_socket(logger, check->sockaddr->ss_family);
    check->epoll_fd = create_epoll(check->socket);
#endif

    struct timespec sent_time;
    struct timespec rcvd_time;

    // construct packet and send
    memset(check->rcv_buffer, 0, PACKETSIZE);

    initialize_packet(check->snd_buffer, check->sockaddr->ss_family, check->address);

    // Send the message
#if DEBUG
    sprint_debug(logger, "Message sent: %s\n", check->snd_buffer + 8);
#endif

    if (check->socket < 0 || check->epoll_fd < 0) {
        check->socket = create_socket(logger, check->sockaddr->ss_family);
        check->epoll_fd = create_epoll(check->socket);
    }

    // Start the clock. Uses CLOCK_REALTIME to get an
    // accurate measure of the latency
    clock_gettime(CLOCK_REALTIME, &sent_time);

    int bytes_sent = 0;
    int tries = 0;

    do {
        if (check->sockaddr->ss_family == AF_INET) {
            bytes_sent = sendto(check->socket, check->snd_buffer, PACKETSIZE, flags, (struct sockaddr *)check->sockaddr, sizeof(struct sockaddr_in));
        } else {
            bytes_sent = sendto(check->socket, check->snd_buffer, PACKETSIZE, flags, (struct sockaddr*)check->sockaddr, sizeof(struct sockaddr_in6));
        }

        if (tries >= 3) {
            sprint_error(logger, "Unable to send ping: %s\n", strerror(errno));

            close(check->socket);
            close(check->epoll_fd);

            check->socket = create_socket(logger, check->sockaddr->ss_family);
            check->epoll_fd = create_epoll(check->socket);

            return (-1);
        }

        if (bytes_sent < 0) { // error
            close(check->socket);
            close(check->epoll_fd);
            
            check->socket = create_socket(logger, check->sockaddr->ss_family);
            check->epoll_fd = create_epoll(check->socket);

            sprint_debug(logger, "Created new socket for %s\n", check->address);
        } else { // this holds: bytes >= 0
            if (bytes_sent == 64) break;
            sprint_error(logger, "Only sent %d out of 64 bytes.\n", bytes_sent);

            return (-1);
        }
        tries++;
    } while(1);

    // receive
    struct epoll_event events[1];
    
    int num_ready = epoll_wait(check->epoll_fd, events, 1, check->timeout * 1e3);

    if (num_ready < 0) {
        // Do not print if we got interrupted
        if (errno != EINTR) {
            sprint_debug(logger, "Unable to receive: %s\n", strerror(errno));
        } else {
            // TODO: maybe return that an interrupt occured
        }

        check->timeout = -1.0;
        
        close(check->socket);
        close(check->epoll_fd);
        check->socket = -1;
        check->epoll_fd = -1;

        return 0;
    } else if (num_ready == 0) { // timeout
        clock_gettime(CLOCK_REALTIME, &rcvd_time);

        double diff = calculate_difference(sent_time, rcvd_time);

        sprint_debug(logger, "Timeout after %1.2fms\n", diff * 1e3);

        check->latency = -1.0;

        close(check->socket);
        close(check->epoll_fd);
        check->socket = -1;
        check->epoll_fd = -1;

        return 0;
    }

    if(events[0].events & EPOLLIN) {
#if DEBUG
        sprint_debug(logger, "Socket %d got some data\n", events[0].data.fd);
#endif
        size_t bytes_rcved = recv(check->socket, check->rcv_buffer, PACKETSIZE, 0);
        
        if (bytes_rcved != 64) {
            sprint_debug(logger, "just received: %zd bytes: %s\n", bytes_rcved, check->rcv_buffer);

            return (-1);
        }
    }

    clock_gettime(CLOCK_REALTIME, &rcvd_time);

    // check if the message matches
    int difference = memcmp(check->snd_buffer + 8, check->rcv_buffer + 8, PACKETSIZE - 8);
    int is_exact_match = difference == 0; 

    if (!is_exact_match) {
        sprint_debug(logger, "Difference: %d\n", difference);
        sprint_debug(logger, "Expected %s\n", check->snd_buffer + 8);
        sprint_debug(logger, "Got      %s\n", check->rcv_buffer + 8);
    }

    if (is_exact_match) {
        check->latency = calculate_difference(sent_time, rcvd_time);
    } else {
        check->latency = -1.0;
        
        close(check->socket);
        close(check->epoll_fd);
        check->socket = -1;
        check->epoll_fd = -1;
    }

    return is_exact_match;
}
