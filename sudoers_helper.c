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

#define PASSWD_CMDS_SPLITTER                       '\n'

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
    if (buffer == NULL) {
        trace("Reallocate memory for string: %s failed.\n", str);
        return NULL;
    }

    memcpy(buffer + buffer_len, str, str_len);
    buffer[buffer_len + str_len] = 0;

    return buffer;
}

/*
    Check if have next line, need handle the escape backslash case, for example:
        Not have next line:  example line \\\\
        Have next line:  example line \\\
    For more information, please check:
        Long lines can be continued with a backslash (‘\’) as the last character on the line.
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
bool have_next_line(const char *str)
{
    int count = 0;
    /* Use -2 to ignore check last character, because it will always be \n */
    int index = strlen(str) - 2;
    for (;index >= 0; index--) {
        if (str[index] != '\\') {
            break;
        }
        
        count++;
    }

    return count % 2;
}

/*
    Load PASSWD_CMDS from sudoers.
    For more information please check:
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
char* load_passwd_cmds(const char *setting_path)
{
    FILE *setting_file= fopen(setting_path, "rt");
    if(setting_file == NULL) {
        trace("Can't open setting file: %s\n", setting_path);
        return NULL;
    }

    bool load_next_line = false;
    char *passwd_cmds = NULL;
    char line_buffer[MAX_LINE_SIZE+1];
    while (fgets(line_buffer, sizeof(line_buffer), setting_file)) {
        char* token;
        if (load_next_line) {
            token = line_buffer;
        }
        else {
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

        load_next_line = have_next_line(token);

        /* Append PASSWD_CMDS to buffer*/
        passwd_cmds = append_string_to_buffer(passwd_cmds, token);
        if (passwd_cmds == NULL) {
            trace("Append PASSWD_CMDS to buffer failed.\n");
            break;
        }
    }

    fclose(setting_file);

    escape_characters(passwd_cmds);
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
        if (*src_pos == ',') {
            /* PASSWD_CMDS use comma as splitter, replace it wiith \n to simplify split handling */
            *dest_pos = PASSWD_CMDS_SPLITTER;
            src_pos++;
            dest_pos++;
            continue;
        }
        else if (*src_pos != '\\') {
            /* copy none escape characters */
            if (dest_pos != src_pos) {
                *dest_pos = *src_pos;
            }

            src_pos++;
            dest_pos++;
            continue;
        }

        /* Handle escape characters */
        src_pos++;
        switch (*src_pos)
        {
            case '!':
            case '=':
            case '"':
            case ',':
            case '(':
            case ')':
            case '\\':
                *dest_pos = *src_pos;
                dest_pos++;
                src_pos++;
                continue;
            case '\n':
                /* Long lines can be continued with a backslash */
                src_pos++;
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
    char* passwd_cmd = passwd_cmds;
    bool start_new_passwd_cmd = true;
    for (int index=0; index < passwd_cmds_length; index++) {
        if (start_new_passwd_cmd) {
            /*
                Set the passwd_cmd point to new command when:
                    1. beginning of passwd_cmds.
                    2. After a comma splitter.
            */
            passwd_cmd = passwd_cmds + index;
            start_new_passwd_cmd = false;
        }

        if (passwd_cmds[index] != PASSWD_CMDS_SPLITTER) {
            continue;
        }

        /* Found a splitter, handle current passwd_cmd. */
        passwd_cmds[index] = 0;
        result = append_password_regex(passwd_cmd);
        if (result != INITIALIZE_SUCCESS) {
            trace("Append password regex failed: %s, result: %d\n", passwd_cmd, result);
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
    result = append_password_regex(passwd_cmd);
    if (result != INITIALIZE_SUCCESS) {
        trace("Append password regex failed: %s, result: %d\n", passwd_cmd, result);
    }

    free(passwd_cmds);
    return result;
}