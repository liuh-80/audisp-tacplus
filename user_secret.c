#include "user_secret.h"

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>

/* Macros for have_next_line result */
#define HAVE_NEXT_SETTING_LINE 1
#define NO_NEXT_SETTING_LINE   0

/* Macros for user secret regex */
#define USER_SECRET_REGEX_WHITE_SPACE "\\s*"
#define USER_SECRET_REGEX_SECRET "(\\S*)"

/* Regex match group count */
#define REGEX_MATCH_GROUP_COUNT      1

/* The command alias prefix */
static const char* COMMAND_ALIAS = "Cmnd_Alias";

/* The user secret setting */
static const char* USER_SECRET_SETTING = "PASSWD_CMDS";

/* Regex list */
REGEX_NODE *global_regex_list = NULL;

/* Append regex to list */
int append_regex(regex_t regex)
{
    /* Create and initialize regex node */
    REGEX_NODE *new_regex_node = (REGEX_NODE*)malloc(sizeof(REGEX_NODE));
    if (new_regex_node == NULL)
    {
        /* When allocate memory failed, stop and return. also output log to both syslog and stderr with LOG_PERROR*/
        syslog(LOG_PERROR, "audisp-tacplus: failed to allocate memory for regex node.\n");
        return REGEX_APPEND_FAILED;
    }

    new_regex_node->next = NULL;
    new_regex_node->regex = regex;

    /* Find the pointer to the latest plugin node's 'next' field */
    REGEX_NODE **current_node = &global_regex_list;
    while (*current_node != NULL) {
        current_node = &((*current_node)->next);
    }
    
    /* append new plugin to tail node */
    *current_node = new_regex_node;
    return REGEX_APPEND_SUCCESS;
}

/* Free loaded regex */
void free_regex()
{
    if (global_regex_list == NULL) {
        return;
    }

    /* Walk to last plugin */
    REGEX_NODE *next_node = global_regex_list;
    while (next_node != NULL) {
        /* Continue with next pligin */
		REGEX_NODE* current_node_memory = next_node;
        next_node = next_node->next;
        
		/* Free node memory, this may also reset all allocated memory depends on c lib implementation */
		free(current_node_memory);
    }

    /* Reset list */
	global_regex_list = NULL;
}

/* Replace user secret with regex */
int fix_user_secret_by_regex(const char* command, char* result_buffer, size_t buffer_size, regex_t regex)
{
    regmatch_t pmatch[REGEX_MATCH_GROUP_COUNT];
    if (regexec(&regex, command, REGEX_MATCH_GROUP_COUNT, pmatch, 0) == REG_NOMATCH) {
        printf("Not found user secret.\n");
        return USER_SECRET_NOT_FOUND;
    }
    
    /* Found user secret between pmatch[0].rm_so to pmatch[0].rm_eo, replace it. */
    printf("Found user secret between: %d -- %d\n", pmatch[0].rm_so, pmatch[0].rm_eo);
    return USER_SECRET_FIXED;
}

/* Replace user secret with regex */
int fix_user_secret(const char* command, char* result_buffer, size_t buffer_size)
{
    if (global_regex_list == NULL) {
        return 0;
    }

    regmatch_t  pmatch[1];
    regoff_t    off, len;

    /* Check every regex */
    REGEX_NODE *next_node = global_regex_list;
    while (next_node != NULL) {
        /* Try fix user secret with current regex */
        if (fix_user_secret_by_regex(command, result_buffer, buffer_size, next_node->regex) == USER_SECRET_FIXED) {
            return USER_SECRET_FIXED;
        }
        
        /* Continue with next regex */
        next_node = next_node->next;
    }
    
    return USER_SECRET_NOT_FOUND;
}

/* Trim start */
char* trim_start(char *str)
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
        if (isspace(*endpos)) {
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

/* Append user secret setting
 * If the resulting longer than buffer size, the remaining characters are discarded and not stored.
 */
void convert_secret_setting_to_regex(char *buf, size_t buf_size, const char* secret_setting)
{
    int dest_idx = 0, src_idx = 0;
    int last_char_is_whitespace = 0;

    /* Reset buffer, make sure following code in while loop can work. */
    memset(buf, 0, buf_size);

    while (secret_setting[src_idx]) {
        int buffer_used_space= strlen(buf);
        if (secret_setting[src_idx] == '*') {
            /* Replace * to (\S*) */
            snprintf(buf + buffer_used_space, buf_size - buffer_used_space,USER_SECRET_REGEX_SECRET);
        }
        else if (isspace(secret_setting[src_idx])) {
            /* Ignore mutiple input space */
            if (!last_char_is_whitespace) {
                /* Replace space to regex \s* which match multiple space */
                snprintf(buf + buffer_used_space, buf_size - buffer_used_space,USER_SECRET_REGEX_WHITE_SPACE);
            }
        }
        else if (buffer_used_space < buf_size - 1){
            /* Copy regular characters */
            buf[buffer_used_space] = secret_setting[src_idx];
        }
        else {
            /* Buffer full, return here. */
            return;
        }

        last_char_is_whitespace = isspace(secret_setting[src_idx]);
        src_idx++;
    }
}

/* Append user secret setting */
int append_user_secret_setting(const char *setting_str)
{
    printf("Append user secret regex: %s\n", setting_str);
    
    /* convert the setting string to regex */
    char regex_buffer[MAX_LINE_SIZE];
    convert_secret_setting_to_regex(regex_buffer, sizeof(regex_buffer), setting_str);
    
    regex_t regex;
    if (regcomp(&regex, regex_buffer, REG_NEWLINE)) {
        return INITIALIZE_INCORRECT_REGEX;
    }
    
    /* Append regex to global list */
    append_regex(regex);
    
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