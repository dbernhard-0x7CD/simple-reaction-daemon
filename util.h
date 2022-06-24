
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
char* escape_servicename(char*);


/*
* Checks if the string 'str' ends with 'end'
*/
int ends_with(char* str, char* end);

#endif