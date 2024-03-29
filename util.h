#ifndef SRD_UTIL_H
#define SRD_UTIL_H

#include <stdint.h>
#include <time.h>

#include "srd.h"
#include "printing.h"
#include "actions.h"
struct timespec;
struct sockaddr_storage;

#define FLAG_CONTAINS_MS         0b1
#define FLAG_CONTAINS_NOW        0b10
#define FLAG_CONTAINS_SDT        0b100
#define FLAG_CONTAINS_SUT        0b1000
#define FLAG_CONTAINS_DOWNTIME   0b10000
#define FLAG_CONTAINS_UPTIME     0b100000
#define FLAG_CONTAINS_LAT_MS     0b1000000
#define FLAG_CONTAINS_STATUS     0b10000000
#define FLAG_CONTAINS_TIMESTAMP  0b100000000

#define DNS_RESOLVE_TIMEOUT 2

/*
 * Returns 1 if the given character needs to be escaped.
 */
int needs_escaping(char c);

/*
 * Accepts a service name and returns the same service name escaped.
 * Each character not in [a-Z] or [0-9] will get escaped to '_HEX' where HEX is
 * the HEX value of the value
 */
char *escape_servicename(const char *);

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
 * more than one day. dt_string should be at least 23 chars.
 */
void seconds_to_string(const int seconds, char* dt_string);

/*
 * Converts seconds to a string in the following format:
 * [%d days] %h:%m:%s.%ms. Where %d is only contained if it's
 * more than one day. dt_string should be at least 23 chars.
 */
void ms_to_string(const int ms, char* dt_string);

/*
 * Prints the time given by 'time' in the given format into str_time.
 */
void format_time(const placeholder_t* format, char* str_time, const size_t len, const struct timespec* time);

/*
 * Returns the bitmap where all replacements are set.
 */
replacement_info_t get_replacements(const char* message);

/*
 * Replaces all placeholders inside raw_message and returns a pointer to the updated string (which must be free'd).
 */
char* insert_placeholders(const placeholder_t* placeholder,
                        const connectivity_check_t* check,
                        const double downtime,
                        const double uptime,
                        const int connected);

/*
 * Calculates the difference in seconds of old and new
 */
double calculate_difference(const struct timespec old, const struct timespec new);

/*
 * Calculates the difference in milliseconds of old and new.
 */
int32_t calculate_difference_ms(const struct timespec old, const struct timespec new);

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
int ping(const logger_t *logger, connectivity_check_t* check);

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
int to_sockaddr(const char* address, struct sockaddr_storage* socket_addr);

/*
 * Tries to resolve hostname into an IP inside socket_addr.
 * Returns 1 on success, else 0.
 */
int resolve_hostname(const logger_t* logger, const char *hostname, struct sockaddr_storage *socket_addr, float timeout_s);

#endif
