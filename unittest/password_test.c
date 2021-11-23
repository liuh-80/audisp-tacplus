#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mock_helper.h"
#include "regex_helper.h"
#include "sudoers_helper.h"
#include "trace.h"
#include "password.h"

/* Regex list */
extern REGEX_NODE *global_regex_list;

int clean_up() {
  return 0;
}

int start_up() {
  return 0;
}

/* Test load password setting*/
void testcase_load_password_setting() {
    set_test_scenario(TEST_SCEANRIO_LOAD_USER_SECRET_SETTING);
    initialize_password_setting("./sudoers");

    int loaded_regex_count = 0;
    REGEX_NODE *next_node = global_regex_list;
    while (next_node != NULL) {
        /* Continue with next pligin */
        REGEX_NODE* current_node_memory = next_node;
        next_node = next_node->next;
        
        loaded_regex_count++;
    }

    release_password_setting();

    CU_ASSERT_EQUAL(loaded_regex_count, 3);
}

/* Test convert setting string to regex string*/
void testcase_convert_passwd_cmd_to_regex() {
    char regex_buffer[MAX_LINE_SIZE];
    
    /* '*' in input setting should replace to (\S*) */
    convert_passwd_cmd_to_regex(regex_buffer, sizeof(regex_buffer), "testcommand    *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
    CU_ASSERT_STRING_EQUAL(regex_buffer, "testcommand[[:space:]]*\\([^[:space:]]*\\)");

    convert_passwd_cmd_to_regex(regex_buffer, sizeof(regex_buffer), "/usr/sbin/chpasswd *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
    CU_ASSERT_STRING_EQUAL(regex_buffer, "/usr/sbin/chpasswd[[:space:]]*\\([^[:space:]]*\\)");
}

/* Test fix password by regex*/
void testcase_fix_password_by_regex() {
    char regex_buffer[MAX_LINE_SIZE];
    char result_buffer[MAX_LINE_SIZE];

    /* '*' in input setting should replace to (\S*) */
    convert_passwd_cmd_to_regex(regex_buffer, sizeof(regex_buffer), "testcommand    *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
    
    /* Fixed regex should be a correct regex */
    regex_t regex;
    CU_ASSERT_FALSE(regcomp(&regex, regex_buffer, REG_NEWLINE));
    
    /* Password should be removed by regex */
    snprintf(result_buffer, sizeof(result_buffer), "%s", "testcommand  testsecret");
    remove_password_by_regex(result_buffer, regex);
    
    debug_printf("Fixed command: %s\n", result_buffer);
    CU_ASSERT_STRING_EQUAL(result_buffer, "testcommand  **********");
}

/* Test fix password*/
void testcase_fix_password() {
    char result_buffer[MAX_LINE_SIZE];
    initialize_password_setting("./sudoers");

    /* Password should be removed by regex */
    snprintf(result_buffer, sizeof(result_buffer), "%s", "/usr/local/bin/config tacacs passkey  testsecret");
    remove_password(result_buffer);

    debug_printf("Fixed command: %s\n", result_buffer);
    CU_ASSERT_STRING_EQUAL(result_buffer, "/usr/local/bin/config tacacs passkey  **********");

    snprintf(result_buffer, sizeof(result_buffer), "%s", "/usr/sbin/chpasswd   testsecret");
    remove_password(result_buffer);

    debug_printf("Fixed command: %s\n", result_buffer);
    CU_ASSERT_STRING_EQUAL(result_buffer, "/usr/sbin/chpasswd   **********");

    snprintf(result_buffer, sizeof(result_buffer), "%s", "/usr/sbin/setpasswd   testsecret");
    remove_password(result_buffer);

    debug_printf("Fixed command: %s\n", result_buffer);
    CU_ASSERT_STRING_EQUAL(result_buffer, "/usr/sbin/setpasswd   **********");

    /* Regular command not change */
    snprintf(result_buffer, sizeof(result_buffer), "%s", "command no password");
    remove_password(result_buffer);
    CU_ASSERT_STRING_EQUAL(result_buffer, "command no password");

    release_password_setting();
}

/* Test release all regex */
void testcase_release_all_regex() {
    set_memory_allocate_count(0);
    
    initialize_password_setting("./sudoers");
    release_password_setting();

    /* All memory should free */
    CU_ASSERT_EQUAL(get_memory_allocate_count(), 0);
}

int main(void) {
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    CU_pSuite ste = CU_add_suite("plugin_test", start_up, clean_up);
    if (NULL == ste) {
    CU_cleanup_registry();
        return CU_get_error();
    }

    if (CU_get_error() != CUE_SUCCESS) {
    fprintf(stderr, "Error creating suite: (%d)%s\n", CU_get_error(), CU_get_error_msg());
        return CU_get_error();
    }

    if (!CU_add_test(ste, "Test testcase_load_password_setting()...\n", testcase_load_password_setting)
      || !CU_add_test(ste, "Test testcase_convert_passwd_cmd_to_regex()...\n", testcase_convert_passwd_cmd_to_regex)
      || !CU_add_test(ste, "Test testcase_fix_password_by_regex()...\n", testcase_fix_password_by_regex)
      || !CU_add_test(ste, "Test testcase_fix_password()...\n", testcase_fix_password)
      || !CU_add_test(ste, "Test testcase_release_all_regex()...\n", testcase_release_all_regex)) {
    CU_cleanup_registry();
        return CU_get_error();
    }

    if (CU_get_error() != CUE_SUCCESS) {
        fprintf(stderr, "Error adding test: (%d)%s\n", CU_get_error(), CU_get_error_msg());
    }

    // run all test
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_ErrorCode run_errors = CU_basic_run_suite(ste);
    if (run_errors != CUE_SUCCESS) {
        fprintf(stderr, "Error running tests: (%d)%s\n", run_errors, CU_get_error_msg());
    }

    CU_basic_show_failures(CU_get_failure_list());

    // use failed UT count as return value
    return CU_get_number_of_failure_records();
}
