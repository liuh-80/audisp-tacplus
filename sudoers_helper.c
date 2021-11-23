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
#define SUDOERS_SETTING_SPLITTER                   " =\t\n"
#define SUDOERS_EQUAL                              "="
#define SUDOERS_LF                                 '\n'

#define PASSWD_CMDS_SPLITTER                       '\r'

/* The command alias prefix */
const char* COMMAND_ALIAS = "Cmnd_Alias";

/* The password setting */
const char* PASSWD_CMDS = "PASSWD_CMDS";

/*
    Load file content.
*/
char* load_file_content(const char *setting_path)
{
    FILE *setting_file = fopen(setting_path, "rt");
    if(setting_file == NULL) {
        trace("Can't open setting file: %s\n", setting_path);
        return NULL;
    }

    fseek(setting_file, 0, SEEK_END);
    size_t setting_file_size = ftell(setting_file);
    fseek(setting_file, 0, SEEK_SET);

    char* file_content = malloc(setting_file_size+1);
    if (file_content == NULL) {
        trace("Allocate memory for file: %s failed.\n", setting_path);
    }
    else {
        size_t result = fread(file_content, sizeof(char), setting_file_size, setting_file);
        if (result == setting_file_size) {
            file_content[setting_file_size] = 0;
        }
        else {
            trace("Read setting file: %s failed.\n", setting_path);
            free(file_content);
            file_content = NULL;
        }
    }

    fclose(setting_file);
    return file_content;
}


/*
    Get setting content length
*/
size_t setting_content_length(const char *setting)
{
    size_t length = 0;
    while (*setting != 0 && *setting != SUDOERS_LF) {
        length++;
        setting++;
    }
    
    return length;
}

/*
    Load PASSWD_CMDS from sudoers.
    For more information please check:
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
char* load_passwd_cmds(const char *setting_path)
{
    char* file_content = load_file_content(setting_path);
    if(file_content == NULL) {
        trace("Load file: %s failed.\n", setting_path);
        return NULL;
    }

    escape_characters(file_content);
    trace("Sudoers content: (%s)\n", file_content);

    char *passwd_cmds = NULL;
    char* token = strtok(file_content, SUDOERS_SETTING_SPLITTER);
    while (token != NULL) {
        trace("Token: (%s)\n", token);
        /* Find Cmnd_Alias */
        if (strncmp(token, COMMAND_ALIAS, strlen(COMMAND_ALIAS))) {
            token = strtok(NULL, SUDOERS_SETTING_SPLITTER);
            continue;
        }

        /* Find PASSWD_CMDS setting */
        token = strtok(NULL, SUDOERS_SETTING_SPLITTER);
        if (strncmp(token, PASSWD_CMDS, strlen(PASSWD_CMDS))) {
            token = strtok(NULL, SUDOERS_SETTING_SPLITTER);
            continue;
        }

        /* Get PASSWD_CMDS setting content */
        token = strtok(NULL, SUDOERS_EQUAL);
        size_t setting_length = setting_content_length(token);
        passwd_cmds = malloc(setting_length+1);
        if (passwd_cmds == NULL) {
            trace("Allocate memory for PASSWD_CMDS buffer failed.\n");
            break;
        }
        
        memcpy(passwd_cmds, token, setting_length);
        passwd_cmds[setting_length] = 0;
        break;
    }

    free(file_content);
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