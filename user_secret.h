#if !defined (USER_SECRED_H)
#define USER_SECRED_H

#include <string.h>
#include <regex.h>

/* Macros for initialize result */
#define INITIALIZE_SUCCESS                         0
#define INITIALIZE_OPEN_SETTING_FILE_FAILED        1
#define INITIALIZE_INCORRECT_REGEX                 2

/* Max setting line buffer size */
#define MAX_LINE_SIZE                              512

/* Regex append result. */
#define REGEX_APPEND_SUCCESS              0
#define REGEX_APPEND_FAILED               1

/* Regex list node. */
typedef struct regex_node {
    struct regex_node *next;
    regex_t regex;
} REGEX_NODE;

/* User secret setting file */
static const char *sudoers_path = "/etc/sudoers";

/* Append user secret setting */
extern void convert_secret_setting_to_regex(char *buf, size_t buflen, const char* secret_setting);

/* Initialize user secret setting */
extern int initialize_user_secret_setting(const char *setting_path);

/* Replace user secret in buffer */
extern void replace_user_secret(const char *buf, size_t buflen);

#endif /* USER_SECRED_H */