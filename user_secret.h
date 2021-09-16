#if !defined (USER_SECRED_H)
#define USER_SECRED_H

#include <string.h>

/* Macros for initialize result */
#define INITIALIZE_SUCCESS                         0
#define INITIALIZE_OPEN_SETTING_FILE_FAILED        1
#define INITIALIZE_INCORRECT_REGEX                 2

/* User secret setting file */
static const char *sudoers_path = "/etc/sudoers";

/* Initialize user secret setting */
extern int initialize_user_secret_setting(const char *setting_path);

/* Replace user secret in buffer */
extern void replace_user_secret(const char *buf, size_t buflen);

#endif /* USER_SECRED_H */