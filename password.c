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
void *mock_realloc(void* ptr, size_t size);
void mock_free(void* ptr);
#define malloc  mock_malloc
#define realloc  mock_realloc
#define free    mock_free
#else
#endif

/* Macros for parse user input */
#define USER_COMMAND_TOKEN_WHITESPACE              " \t\n\r\f"
#define USER_COMMAND_TOKEN_SETTING_SPLITTER        " =\t"
#define USER_COMMAND_TOKEN_EQUAL                   "="
#define USER_COMMAND_TOKEN_COMMA                   ","

#define BUFFER_CRLF              "\n\r"

/* The command alias prefix */
const char* COMMAND_ALIAS = "Cmnd_Alias";

/* The password setting */
const char* PASSWD_CMDS = "PASSWD_CMDS";

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

/* Replace password with PASSWORD_MASK by regex. */
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

/* Find and return the pointer of the first non-space character*/
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

/*
    Escape characters
    For more information, please check:
        The following characters must be escaped with a backslash (‘\’) when used as part of a word (e.g. a user name or host name): ‘!’, ‘=’, ‘:’, ‘,’, ‘(’, ‘)’, ‘\’.
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
void escape_characters(char *str)
{
    char *src_pos=str;
    char *dest_pos=str;
    while (*src_pos) {
        /* copy none escape characters */
        if (*src_pos != '\\') {
            if (dest_pos != src_pos) {
                *dest_pos = *src_pos;
            }
            
            src_pos++;
            dest_pos++;
            continue;
        }

        /* Handle escape characters */
        src_pos++;
        if (*src_pos == '!'
            || *src_pos == '='
            || *src_pos == '"'
            || *src_pos == ','
            || *src_pos == '('
            || *src_pos == ')'
            || *src_pos == '\\') {
            *dest_pos = *src_pos;
            dest_pos++;
            continue;
        }

        /* Not a escape character */
        *dest_pos = '\\';
        dest_pos++;

        *dest_pos = *src_pos;
        src_pos++;
        dest_pos++;
    }

    *dest_pos = 0;
}

/* Append passwd_cmd to global list */
int append_password_setting(char *passwd_cmd)
{
    trace("Append passwd_cmd: %s\n", passwd_cmd);
    /* convert the setting string to regex */
    char regex_buffer[MAX_LINE_SIZE+1];
    escape_characters(passwd_cmd);
    convert_passwd_cmd_to_regex(regex_buffer, sizeof(regex_buffer), passwd_cmd);

    regex_t regex;
    if (regcomp(&regex, regex_buffer, REG_NEWLINE)) {
        trace("Complie regex failed: %s\n", regex_buffer);
        return INITIALIZE_INCORRECT_REGEX;
    }

    /* Append regex to global list */
    append_regex_to_list(regex);

    return INITIALIZE_SUCCESS;
}

/* Append string to buffer. */
char* append_string_to_buffer(char* buffer, char* str)
{
    int str_len = strlen(str);
    int buffer_len = 0;
    if (buffer != NULL) {
        buffer_len = strlen(buffer);
    }

    buffer = realloc(buffer, buffer_len + str_len + 1);

    memcpy(buffer + buffer_len, str, str_len);
    buffer[buffer_len + str_len] = 0;

    return buffer;
}

/*
    Load PASSWD_CMDS from sudoers.
    For more information please check:
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
char* load_passwd_cmds(FILE* file)
{
    int continue_load_password = NO_NEXT_SETTING_LINE;
    char *passwd_cmds = NULL;
    char line_buffer[MAX_LINE_SIZE+1];
    while (fgets(line_buffer, sizeof line_buffer, file)) {
        /* Remove \r\n from buffer */
        line_buffer[strcspn(line_buffer, BUFFER_CRLF)] = 0;

        char* token;
        if (continue_load_password == NO_NEXT_SETTING_LINE) {
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
            if (strncmp(token, PASSWD_CMDS, strlen(PASSWD_CMDS))) {
                /* Ignore current line when current line is not a password setting */
                continue;
            }

            /* Get password setting content */
            token = strtok(NULL, USER_COMMAND_TOKEN_EQUAL);
        }
        else {
            token = line_buffer;
        }

        /*
            Check if have next line
            For more information, please check:
                Long lines can be continued with a backslash (‘\’) as the last character on the line.
                https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
        */
        int cmd_len = strlen(token);
        if (cmd_len > 0 && token[cmd_len-1] == '\\') {
            continue_load_password = HAVE_NEXT_SETTING_LINE;
            token[cmd_len-1] = 0;
        }
        else {
            continue_load_password = NO_NEXT_SETTING_LINE;
        }

        /* Append PASSWD_CMDS to buffer*/
        passwd_cmds = append_string_to_buffer(passwd_cmds, token);
    }

    return passwd_cmds;
}

/*
    Initialize password setting from sudoers.
*/
int initialize_password_setting(const char *setting_path)
{
    int result = INITIALIZE_SUCCESS;
    char line_buffer[MAX_LINE_SIZE+1];
    FILE *setting_file= fopen(setting_path, "r");
    if(setting_file == NULL) {
        return INITIALIZE_OPEN_SETTING_FILE_FAILED;
    }

    char* passwd_cmds = load_passwd_cmds(setting_file);
    fclose(setting_file);

    /* Split PASSWD_CMDS with comma */
    char* passwd_cmd = strtok(passwd_cmds, USER_COMMAND_TOKEN_COMMA);
    while (passwd_cmd != NULL) {
        passwd_cmd = find_non_space(passwd_cmd);
        append_password_setting(passwd_cmd);

        passwd_cmd = strtok(NULL, USER_COMMAND_TOKEN_COMMA);
    }

    free(passwd_cmds);
    return result;
}
