#include "srd.h"
#include "actions.h"
struct timespec;

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
int ends_with(char *str, char *end);

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
 * Writes the current time into str with the given format
 */
void get_current_time(char *str, const int n, const char *format);

/*
 * Replaces all placeholders inside raw_message and returns a pointer to the updated string (which must be free'd).
 */
char *insert_placeholders(const char *raw_message, const connectivity_check_t *check, const conn_state_t state, const struct timespec previous_last_reply, const char *datetime_format, const double diff, const int connected);

/*
 * Calculates the difference in seconds of old and new
 */
double calculate_difference(struct timespec old, struct timespec new);

#endif
