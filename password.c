#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "password.h"
#include "regex_helper.h"
#include "sudoers_helper.h"
#include "trace.h"

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

/* Append passwd_cmd to global list */
int append_password_regex(char *passwd_cmd)
{
    trace("Append passwd_cmd: %s\n", passwd_cmd);

    /* convert the setting string to regex */
    char regex_buffer[MAX_LINE_SIZE+1];
    passwd_cmd = find_non_space(passwd_cmd);
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