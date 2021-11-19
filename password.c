#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "password.h"
#include "regex_helper.h"
#include "trace.h"

// use mock functions when build for UT
#if defined (UNIT_TEST)
void *mock_malloc(size_t size);
void mock_free(void* ptr);
#define malloc  mock_malloc
#define free    mock_free
#else
#endif

/* Macros for have_next_line result */
#define HAVE_NEXT_SETTING_LINE 1
#define NO_NEXT_SETTING_LINE   0

/* Macros for parse user input */
#define USER_COMMAND_TOKEN_WHITESPACE              " \t\n\r\f"
#define USER_COMMAND_TOKEN_SETTING_SPLITTER        " =\t"
#define USER_COMMAND_TOKEN_EQUAL                   "="
#define USER_COMMAND_TOKEN_COMMA                   ","

/* The command alias prefix */
const char* COMMAND_ALIAS = "Cmnd_Alias";

/* The password setting */
const char* PASSWORD_SETTING = "PASSWD_CMDS";

/* Regex list */
REGEX_NODE *global_regex_list = NULL;

/* Append regex to list */
int append_regex_to_list(regex_t regex)
{
    /* Create and initialize regex node */
    REGEX_NODE *new_regex_node = (REGEX_NODE *)malloc(sizeof(REGEX_NODE));
    if (new_regex_node == NULL)
    {
        /* When allocate memory failed, stop and return. also output log to both syslog and stderr with LOG_PERROR*/
        trace("Failed to allocate memory for regex node.\n");
        return REGEX_APPEND_FAILED;
    }

    new_regex_node->next = NULL;
    new_regex_node->regex = regex;

    /* Find the pointer to the latest regex node's 'next' field */
    REGEX_NODE **current_node = &global_regex_list;
    while (*current_node != NULL) {
        current_node = &((*current_node)->next);
    }
    
    /* append new regex to tail node */
    *current_node = new_regex_node;
    return REGEX_APPEND_SUCCESS;
}

/* Release password setting */
void release_password_setting()
{
    if (global_regex_list == NULL) {
        return;
    }

    /* Walk to last regex */
    REGEX_NODE *current = global_regex_list;
    while (current != NULL) {
        /* Continue with next regex */
        REGEX_NODE* current_node_memory = current;
        current = current->next;
        
        /* Free node memory, this may also reset all allocated memory depends on c lib implementation */
        free(current_node_memory);
    }

    /* Reset list */
    global_regex_list = NULL;
}

/* Replace password with regex */
void remove_password(char* command)
{
    if (global_regex_list == NULL) {
        return;
    }

    /* Check every regex */
    REGEX_NODE *next_node = global_regex_list;
    while (next_node != NULL) {
        /* Try fix password with current regex */
        if (remove_password_by_regex(command, next_node->regex) == PASSWORD_REMOVED) {
            return;
        }
        
        /* If password not fix, continue try next regex */
        next_node = next_node->next;
    }
}

/* Find and return the pointer of the first none space character*/
char* find_non_space(char *str)
{
    if (str == NULL) {
        return str;
    }

    while (isspace(*str)) {
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
    while (endpos-- > str) {
        if (!isspace(*endpos)) {
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

/* Append password setting to global list */
int append_password_setting(const char *setting_str)
{
    trace("Append password regex: %s\n", setting_str);

    /* convert the setting string to regex */
    char regex_buffer[MAX_LINE_SIZE];
    convert_passwd_cmd_to_regex(regex_buffer, sizeof(regex_buffer), setting_str);

    regex_t regex;
    if (regcomp(&regex, regex_buffer, REG_NEWLINE)) {
        trace("Complie regex failed: %s\n", regex_buffer);
        return INITIALIZE_INCORRECT_REGEX;
    }

    /* Append regex to global list */
    append_regex_to_list(regex);

    return INITIALIZE_SUCCESS;
}

/* Initialize password setting */
int initialize_password_setting(const char *setting_path)
{
    int result = INITIALIZE_SUCCESS;
    char line_buffer[MAX_LINE_SIZE];
    FILE *setting_file= fopen(setting_path, "r");
    if(setting_file == NULL) {
        return INITIALIZE_OPEN_SETTING_FILE_FAILED;
    }

    int continue_parse_password = 0;
    while (fgets(line_buffer, sizeof line_buffer, setting_file)) {
        char* token;
        if (!continue_parse_password) {
            token = strtok(line_buffer, USER_COMMAND_TOKEN_WHITESPACE);
            if (!token) {
                /* Empty line will not get any token */
                continue;
            }

            /* Not continue check unfinished multiple line settings */
            if (strncmp(token, COMMAND_ALIAS, strlen(COMMAND_ALIAS))) {
                /* Ignore current line when current line is not a command alias */
                continue;
            }

            token = strtok(NULL, USER_COMMAND_TOKEN_SETTING_SPLITTER);
            if (strncmp(token, PASSWORD_SETTING, strlen(PASSWORD_SETTING))) {
                /* Ignore current line when current line is not a password setting */
                continue;
            }

            /* Get password setting content */
            token = strtok(NULL, USER_COMMAND_TOKEN_EQUAL);
        }
        else {
            /* The strok will return setting before first whitespace, so need use origional buffer */
            token = line_buffer;
        }

        /* Check if have next setting line */
        continue_parse_password = check_have_next_line(token);

        /* Get settings before comma */
        token = strtok(token, USER_COMMAND_TOKEN_COMMA);
        token = find_non_space(token);

        /* Append setting regex */
        append_password_setting(token);
    }

    fclose(setting_file);

    return result;
}