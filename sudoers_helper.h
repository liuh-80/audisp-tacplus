#ifndef SUDOERS_HELPER_H
#define SUDOERS_HELPER_H

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
