#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "regex_helper.h"
#include "trace.h"

#define min(a,b)            (((a) < (b)) ? (a) : (b))

/* 
 * Macros for password regex
 * These are BRE regex, please refer to: https://en.wikibooks.org/wiki/Regular_Expressions/POSIX_Basic_Regular_Expressions
 REGEX_WHITESPACES will match the whitespace in user commands.
 REGEX_TOKEN will match password or connection string in user commands
 */
#define REGEX_WHITESPACES              "[[:space:]]*"
#define REGEX_TOKEN                   "\\([^[:space:]]*\\)"

/* Regex match group count, 2 because only have 1 subexpression for password */
#define REGEX_MATCH_GROUP_COUNT      2

/* The password mask */
#define PASSWORD_MASK                   '*'

/* Remove password from command. */
int remove_password_by_regex(char* command, regex_t regex)
{
    regmatch_t pmatch[REGEX_MATCH_GROUP_COUNT];
    if (regexec(&regex, command, REGEX_MATCH_GROUP_COUNT, pmatch, 0) == REG_NOMATCH) {
        trace("User command not match.\n");
        return PASSWORD_NOT_FOUND;
    }

    if (pmatch[1].rm_so < 0) {
        trace("Password not found.\n");
        return PASSWORD_NOT_FOUND;
    }

    /* Found password between pmatch[1].rm_so to pmatch[1].rm_eo, replace it. */
    trace("Found password between: %d -- %d\n", pmatch[1].rm_so, pmatch[1].rm_eo);

    /* Replace password with mask. */
    size_t command_length = strlen(command);
    int password_start_pos = min(pmatch[1].rm_so, command_length);
    int password_count = min(pmatch[1].rm_eo, command_length) - password_start_pos;
    memset(command + password_start_pos, PASSWORD_MASK, password_count);

    return PASSWORD_REMOVED;
}

/* 
    Convert password command to regex.
    Password commands defined in sudoers file, the PASSWD_CMD alias is a list of password command.
    For more information please check:
    https://www.sudo.ws/man/1.7.10/sudoers.man.html
    https://github.com/Azure/sonic-buildimage/blob/5c503b81ae186aa378928edf36fa1d347e919d7a/files/image_config/sudoers/sudoers
 */
void convert_passwd_cmd_to_regex(char *buf, size_t buf_size, const char* password_setting)
{
    int src_idx = 0;
    int last_char_is_whitespace = 0;

    memset(buf, 0, buf_size);
    while (password_setting[src_idx]) {
        int buffer_used_space= strlen(buf);
        if (password_setting[src_idx] == PASSWORD_MASK) {
            /* Replace * to REGEX_TOKEN */
            snprintf(buf + buffer_used_space, buf_size - buffer_used_space,REGEX_TOKEN);
        }
        else if (isspace(password_setting[src_idx])) {
            /* Ignore mutiple whitespace */
            if (!last_char_is_whitespace) {
                /* Replace whitespace to regex REGEX_WHITESPACES which match multiple whitespace */
                snprintf(buf + buffer_used_space, buf_size - buffer_used_space,REGEX_WHITESPACES);
            }
        }
        else if (buffer_used_space < buf_size - 1){
            /* Copy none password characters */
            buf[buffer_used_space] = password_setting[src_idx];
        }
        else {
            /* Buffer full, return here. */
            return;
        }

        last_char_is_whitespace = isspace(password_setting[src_idx]);
        src_idx++;
    }
}