#ifndef SUDOERS_HELPER_H
#define SUDOERS_HELPER_H

/* Macros for have_next_line result */
#define HAVE_NEXT_SETTING_LINE 1
#define NO_NEXT_SETTING_LINE   0

/* passwd_cmd list node. */
typedef struct passwd_cmd_node {
    struct passwd_cmd_node *next;
    char* passwd_cmd;
} PASSWD_CMD_NODE;

/* Load PASSWD_CMDS from sudoers. */
char* load_passwd_cmds(const char *setting_path);

/*
    Escape characters according to sudoers file format.
    For more information, please check:
        The following characters must be escaped with a backslash (‘\’) when used as part of a word (e.g. a user name or host name): ‘!’, ‘=’, ‘:’, ‘,’, ‘(’, ‘)’, ‘\’.
        https://www.sudo.ws/man/1.8.17/sudoers.man.html#Other_special_characters_and_reserved_words
*/
void escape_characters(char *str);

/* Initialize password setting from sudoers. */
int initialize_password_setting(const char *setting_path);

#endif /* SUDOERS_HELPER_H */
