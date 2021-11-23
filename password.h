#ifndef USER_SECRED_H
#define USER_SECRED_H

#include <string.h>
#include <regex.h>

/* Macros for initialize result */
#define INITIALIZE_SUCCESS                         0
#define INITIALIZE_LOAD_SETTING_FAILED             1
#define INITIALIZE_INCORRECT_REGEX                 2

/* Regex append result. */
#define REGEX_APPEND_SUCCESS              0
#define REGEX_APPEND_FAILED               1

/* Regex list node. */
typedef struct regex_node {
    struct regex_node *next;
    regex_t regex;
} REGEX_NODE;

/* Release password setting */
extern void release_password_setting();

/* Replace password with regex */
extern void remove_password(char* command);

/* Append passwd_cmd to global list */
int append_password_regex(char *passwd_cmd);

#endif /* USER_SECRED_H */