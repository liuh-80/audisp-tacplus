#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdbool.h>

#include "password.h"
#include "sudoers_helper.h"
#include "trace.h"

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
char* load_passwd_cmds(const char *setting_path)
{
    FILE *setting_file= fopen(setting_path, "r");
    if(setting_file == NULL) {
        trace("Can't open setting file: %s\n", setting_path);
        return NULL;
    }

    int continue_load_password = NO_NEXT_SETTING_LINE;
    char *passwd_cmds = NULL;
    char line_buffer[MAX_LINE_SIZE+1];
    while (fgets(line_buffer, sizeof line_buffer, setting_file)) {
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

    fclose(setting_file);
    return passwd_cmds;
}

/*
    Escape characters according to sudoers file format.
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

/*
    Handle passwd_cmd, append to password regex setting.
*/
int handle_passwd_cmd(char *passwd_cmd)
{
    if (passwd_cmd == NULL) {
        return INITIALIZE_SUCCESS;
    }

    /*
        Escape after we split passwd_cmds with comma splitter,
        because '\,' will be convert to ',' by escape_characters.
    */
    escape_characters(passwd_cmd);
    int result = append_password_regex(passwd_cmd);
    if (result != INITIALIZE_SUCCESS) {
        trace("Append password regex failed: %s, result: %d\n", passwd_cmd, result);
    }
    
    return result;
}

/*
    Initialize password setting from sudoers.
*/
int initialize_password_setting(const char *setting_path)
{
    char* passwd_cmds = load_passwd_cmds(setting_path);
    if (passwd_cmds == NULL) {
        /* Setting file open failed or can't find password setting. */
        trace("Load PASSWD_CMDS from: %s failed.\n", setting_path);
        return INITIALIZE_LOAD_SETTING_FAILED;
    }

    trace("Loaded PASSWD_CMDS: (%s), from: %s .\n", passwd_cmds, setting_path);

    /* Split PASSWD_CMDS with comma */
    int result = INITIALIZE_SUCCESS;
    int passwd_cmds_length = strlen(passwd_cmds);
    int backslash_count = 0;
    char* passwd_cmd = passwd_cmds;
    bool start_new_passwd_cmd = true;
    for (int index=0; index <= passwd_cmds_length; index++) {
        if (passwd_cmds[index] == '\\') {
            backslash_count++;
        }
        else if (passwd_cmds[index] != ',') {
            backslash_count = 0;

            /*
                Set the passwd_cmd point to new command when:
                    1. beginning of passwd_cmds.
                    2. After a comma splitter.
            */
            if (start_new_passwd_cmd) {
                passwd_cmd = passwd_cmds + index;
                start_new_passwd_cmd = false;
            }

            continue;
        }

        /*
            Comma is a splitter when there are even number of backslash, for example \\, or \\\\,
        */
        bool comma_is_splitter = backslash_count % 2;
        backslash_count = 0;
        if (comma_is_splitter) {
            continue;
        }

        /* We have a comma */
        passwd_cmds[index] = 0;
        result = handle_passwd_cmd(passwd_cmd);
        if (result != INITIALIZE_SUCCESS) {
            break;
        }

        /*
            Set passwd_cmd to NULL, so multiple comma splitter will not create empty passwd_cmd, for example:
                command1,,command2
        */
        passwd_cmd = NULL;
        start_new_passwd_cmd = true;
    }
    
    /*
        Handle following 2 cases:
            1. Comma splitter not exist in PASSWD_CMDS
            2. Last command in PASSWD_CMDS
    */
    result = handle_passwd_cmd(passwd_cmd);

    free(passwd_cmds);
    return result;
}