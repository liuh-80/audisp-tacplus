#include "user_secret.h"

#include <stdio.h>
#include <syslog.h>
#include <regex.h>

/* Macros for have_next_line result */
#define HAVE_NEXT_SETTING_LINE 1
#define NO_NEXT_SETTING_LINE   0

/* User secret setting file */
static const int MAX_LINE_SIZE = 512;

/* The command alias prefix */
static const char* COMMAND_ALIAS = "Cmnd_Alias";

/* The user secret setting */
static const char* USER_SECRET_SETTING = "PASSWD_CMDS";

/* Trim start */
char* trim_start(char *str)
{
    if (str == NULL) {
        return str;
    }
    
    while (*str == ' '
            || *str == '\t'
            || *str == '\f') {
        str++;
    }
    
    return str;
}

/* Check setting if have next line */
int check_have_next_line(const char *str)
{
    if (str == NULL) {
        return NO_NEXT_SETTING_LINE;
    }
    
    /* Find end of string */
    const char* endpos = str;
    while (*endpos) {
        endpos++;
    }
    
    /* Find last none whitespace character */
    char last_none_whitespace_char = 0;
    while (endpos > str) {
        endpos--;
        if (*endpos != ' '
                && *endpos != '\t'
                && *endpos != '\n'
                && *endpos != '\r'
                && *endpos != '\f') {
            last_none_whitespace_char = *endpos;
            break;
        }
    }
    
    /* If the string end with \, then have next setting line */
    if (last_none_whitespace_char == '\\') {
        return HAVE_NEXT_SETTING_LINE;
    }
    
    return NO_NEXT_SETTING_LINE;
}

/* Append user secret setting */
void convert_secret_setting_to_regex(char *buf, size_t buflen, const char* secret_setting)
{
    int dest_idx = src_idx = 0;
    while (dest_idx < buflen
            && secret_setting[src_idx] != '\0') {
        if (secret_setting[src_idx] == '*') {
            /* Replace * to (.*) */
            buf[dest_idx] = '(';
            buf[dest_idx] = '.';
            buf[dest_idx] = '*';
            buf[dest_idx] = ')';
            dest_idx++;
            src_idx++;
        }
        else {
            buf[dest_idx] = secret_setting[src_idx];
            dest_idx++;
            src_idx++;
        }
    }
    
    buf[dest_idx] = '\0';
}

/* Append user secret setting */
int append_user_secret_setting(const char *setting_str)
{
    printf("Append user secret regex: %s\n", setting_str);
    
    /* convert the setting string to regex */
    char regex_buffer[MAX_LINE_SIZE];
    convert_secret_setting_to_regex(regex_buffer, sizeof(regex_buffer), setting_str)
    
    regex_t regex;
    if (regcomp(&regex, regex_buffer, REG_NEWLINE)) {
        return INITIALIZE_INCORRECT_REGEX;
    }
    
    return INITIALIZE_SUCCESS;
}

/* Initialize user secret setting */
int initialize_user_secret_setting(const char *setting_path)
{
    int result = INITIALIZE_SUCCESS;
    char line_buffer[MAX_LINE_SIZE];
    FILE *setting_file= fopen(setting_path, "r");
    if(setting_file == NULL) {
        return INITIALIZE_OPEN_SETTING_FILE_FAILED;
    }

    int continue_parse_user_secret = 0;
    while (fgets(line_buffer, sizeof line_buffer, setting_file)) {
        char* token;
        if (!continue_parse_user_secret) {
            token = strtok(line_buffer, " \t\n\r\f");
            if (!token) {
                /* Empty line will not get any token */
                continue;
            }
            
            /* Not continue check unfinished multiple line settings */
            if (strncmp(token, COMMAND_ALIAS, sizeof(COMMAND_ALIAS))) {
                /* Ignore current line when current line is not a command alias */
                continue;
            }

            token = strtok(NULL, " =\t");
            if (strncmp(token, USER_SECRET_SETTING, sizeof(USER_SECRET_SETTING))) {
                /* Ignore current line when current line is not a user secret setting */
                continue;
            }
            
            /* Get user secret setting content */
            token = strtok(NULL, "=");
        }
        else {
            /* The strok will return setting before first whitespace, so need use origional buffer */
            token = line_buffer;
        }

        /* Check if have next setting line */
        continue_parse_user_secret = check_have_next_line(token);
        
        /* Get settings before ',' */
        token = strtok(token, ",");
        token = trim_start(token);
        
        /* Append setting regex */
        result = append_user_secret_setting(token);
        if (result != INITIALIZE_SUCCESS) {
            break;
        }
    }

    fclose(setting_file);

    return result;
}

/* Replace user secret in buffer */
void replace_user_secret(const char *buf, size_t buflen)
{
}