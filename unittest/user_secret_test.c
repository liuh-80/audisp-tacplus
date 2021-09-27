#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "user_secret.h"
#include "mock_helper.h"

int clean_up() {
  return 0;
}

int start_up() {
  return 0;
}

/* Test load user secret setting*/
void testcase_load_user_secret_setting() {
	set_test_scenario(TEST_SCEANRIO_LOAD_USER_SECRET_SETTING);
	
	initialize_user_secret_setting("./sudoers");

	//CU_ASSERT_STRING_EQUAL(mock_itrace_message_buffer, "Plugin: can't load plugin ./testplugin.so: MOCK error\n");
}

/* Test convert setting string to regex string*/
void testcase_convert_secret_setting_to_regex() {
    char regex_buffer[MAX_LINE_SIZE];
    
    /* '*' in input setting should replace to (\S*) */
    convert_secret_setting_to_regex(regex_buffer, sizeof(regex_buffer), "testcommand    *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
	CU_ASSERT_STRING_EQUAL(regex_buffer, "testcommand\\s*(\\S*)");

    convert_secret_setting_to_regex(regex_buffer, sizeof(regex_buffer), "/usr/sbin/chpasswd *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
	CU_ASSERT_STRING_EQUAL(regex_buffer, "/usr/sbin/chpasswd\\s*(\\S*)");
}

/* Test fix user secret by regex*/
void testcase_fix_user_secret_by_regex() {
    char regex_buffer[MAX_LINE_SIZE];
    char result_buffer[MAX_LINE_SIZE];
    
    /* '*' in input setting should replace to (\S*) */
    convert_secret_setting_to_regex(regex_buffer, sizeof(regex_buffer), "testcommand    *");
    debug_printf("regex_buffer: %s\n", regex_buffer);
    
    /* Fixed regex should be a correct regex */
    regex_t regex;
	CU_ASSERT_FALSE(regcomp(&regex, regex_buffer, REG_NEWLINE));
    
    /* User secret should be removed by regex */
    CU_ASSERT_EQUAL(fix_user_secret_by_regex("testcommand testsecret", result_buffer, sizeof(result_buffer), regex), USER_SECRET_FIXED);
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

  if (!CU_add_test(ste, "Test testcase_load_user_secret_setting()...\n", testcase_load_user_secret_setting)
      || !CU_add_test(ste, "Test testcase_convert_secret_setting_to_regex()...\n", testcase_convert_secret_setting_to_regex)
      || !CU_add_test(ste, "Test testcase_fix_user_secret_by_regex()...\n", testcase_fix_user_secret_by_regex)) {
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
