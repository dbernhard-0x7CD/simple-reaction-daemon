#include <stdint.h>
#include <sys/un.h>
#include <time.h>

#include "srd.h"
#include "printing.h"
struct timespec;
struct sockaddr_storage;


#ifndef SRD_UTIL_H
#define SRD_UTIL_H

/*
 * Returns 1 if the given character needs to be escaped.
 */
int needs_escaping(char c);

/*
 * Accepts a service name and returns the same service name escaped.
 * Each character not in [a-Z] or [0-9] will get escaped to '_HEX' where HEX is
 * the HEX value of the value
 */
char *escape_servicename(char *);

/*
 * Checks if the string 'str' ends with 'end'
 */
int ends_with(const char *str, const char *end);

/*
 * Returns a pointer to the string 'string' where substr was replaced with
 * replacement.
 */
char *str_replace(const char *string, const char *substr, const char *replacement);

/*
 * Returns a pointer to the string of the IP of the gateway.
 * Returns NULL if an error occurs.
 */
char *get_default_gw();

/*
 * Converts seconds to a string in the following format:
 * [%d days] %h:%m:%s. Where %d is only contained if it's
 * more than one day.
 */
void seconds_to_string(int seconds, char* dt_string);

/*
 * Writes the current time into str with the given format.
 * str_len denotes the maximum length str may be (including nul terminator). timestamp will contain the used time (if it is not NULL)
 */
void get_current_time(char *str, const int str_len, const char *format, time_t* timestamp);

/*
 * Replaces all placeholders inside raw_message and returns a pointer to the updated string (which must be free'd).
 */
char *insert_placeholders(const char *raw_message, const connectivity_check_t *check, const char *datetime_format, const double downtime_s, const double uptime_s, const int connected);

/*
 * Calculates the difference in seconds of old and new
 */
double calculate_difference(struct timespec old, struct timespec new);

/*
 * Calculates the difference in milliseconds of old and new.
 */
int32_t calculate_difference_ms(struct timespec old, struct timespec new);

/*
 * Adds to timespec structs.
 */
struct timespec timespec_add(const struct timespec t1, const struct timespec t2);


/*
 * Creates a default socket used for pinging. 
 */
int create_socket(const logger_t* logger, const int address_family);

/*
* Pings the given address and updates latency_s.
* Returns 1 if the ping was successfully returned. 
* If nothing was returned 0 is returned. Errors are
* indicated by any negative value.
*/
int ping(const logger_t *logger,
        int* sd,
        int* epoll_fd,
        const char *adress,
        double *latency_s,
        const double timeout_s);

/*
 * Creates an epoll fd used to get notified when a message was received on the fd.
 */
int create_epoll(const int fd);

/*
 * Converts the address as string into a sockaddr_in.
 * Sets address_family to AF_INET if it's an IPv4 address,
 * and to AF_INET6 if it's an IPv6 address.
 * Returns 1 on success, else 0.
 */
int to_sockaddr(const char* address, struct sockaddr_storage* socket_addr, sa_family_t* address_family);

/*
 * Tries to resolve hostname into an IP iside socket_addr.
 * Returns 1 on success, else 0.
 */
int resolve_hostname(const logger_t* logger, const char *hostname, struct sockaddr_storage *socket_addr, sa_family_t* address_family);

#endif
