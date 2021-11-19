#ifndef USER_SECRED_H
#define USER_SECRED_H

#include <string.h>
#include <regex.h>

/* Macros for initialize result */
#define INITIALIZE_SUCCESS                         0
#define INITIALIZE_OPEN_SETTING_FILE_FAILED        1
#define INITIALIZE_INCORRECT_REGEX                 2

/* Regex append result. */
#define REGEX_APPEND_SUCCESS              0
#define REGEX_APPEND_FAILED               1

/* Regex list node. */
typedef struct regex_node {
    struct regex_node *next;
    regex_t regex;
} REGEX_NODE;

/* Initialize password setting */
extern int initialize_password_setting(const char *setting_path);

/* Release password setting */
extern void release_password_setting();

/* Replace password with regex */
extern void remove_password(char* command);

#endif /* USER_SECRED_H */