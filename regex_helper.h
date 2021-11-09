#ifndef REGEX_HELPER_H
#define REGEX_HELPER_H

#include <regex.h>
#include <string.h>

/* Replace user secret with regex */
extern char * remove_user_secret_by_regex(const char* command, regex_t regex);

/* Convert user secret setting to regex. */
extern void convert_secret_setting_to_regex(char *buf, size_t buf_size, const char* secret_setting);

#endif /* REGEX_HELPER_H */