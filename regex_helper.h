#ifndef REGEX_HELPER_H
#define REGEX_HELPER_H

#include <regex.h>
#include <string.h>

/* Regex fix result. */
#define PASSWORD_REMOVED                 0
#define PASSWORD_NOT_FOUND             1

/* Remove password from command. */
extern int remove_password_by_regex(char* command, regex_t regex);

/* Convert password setting to regex. */
extern void convert_passwd_cmd_to_regex(char *buf, size_t buf_size, const char* password_setting);

#endif /* REGEX_HELPER_H */