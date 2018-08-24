
/* This test creates a client and a server, to test the configure file options for the SSA-daemon.
 * It forks a server to listen for incomming connections and evaluate them for
 * corectness. If the ssa does not behave as expected the server will exit with
 * a non-zero return code and the sigchild handler will be called notifying
 * the test program that an error was discovered. The state of the program
 * may then be printed before termination, or logged depending on future
 * implementation decisions.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include "../../in_tls.h"
#include "../../config.h"

#define NO_APP_CUSTOM		"cfgFiles/no_app_custom.cfg"
#define NO_CACHE_TIMEOUT	"cfgFiles/no_cache_timeout.cfg"
#define NO_CIPHER_SUITE		"cfgFiles/no_cipher_suite.cfg"
#define NO_MIN_PROTOCOL 	"cfgFiles/no_min_protocol.cfg"
#define NO_PROFILES		"cfgFiles/no_profiles.cfg"
#define NO_TRUST_STORE	 	"cfgFiles/no_trust_store.cfg"
#define NO_VALIDATION		"cfgFiles/no_validation.cfg"
#define ONE_PROFILE	 	"cfgFiles/one_profile.cfg"
#define VALID_FILE		"cfgFiles/valid.cfg"
#define a	"cfgFiles/.cfg"
#define b	"cfgFiles/.cfg"
#define c	"cfgFiles/.cfg"
#define d	"cfgFiles/.cfg"
#define e	"cfgFiles/.cfg"
#define BUFFER_SIZE	100

#define PASS 1
#define FAIL 0
#define RESULT_POSITION 65
#define PASSED_TEST "\x1B[32mPASSED\x1B[0m" 
#define FAILED_TEST "\x1B[31mFAILED\x1B[0m"

typedef int (*test_funct_t)(void);
typedef struct {
	test_funct_t func;
	char* name;
}test_t;


//testing parse_config(char* filename) Branch Coverage
int test_parse_config_no_file			(void);
int test_parse_config_no_validation		(void);
int test_parse_config_no_app_custom		(void);
int test_parse_config_no_trust_store		(void);
int test_parse_config_no_min_protocol		(void);
int test_parse_config_no_cipher_suite		(void);
int test_parse_config_no_cache_timeout		(void);

int test_parse_config_invalid_file		(void);
int test_parse_config_invalid_validation	(void);
int test_parse_config_invalid_app_custom	(void);
int test_parse_config_invalid_trust_store	(void);
int test_parse_config_invalid_min_protocol	(void);
int test_parse_config_invalid_max_protocol	(void);
int test_parse_config_invalid_cipher_suite	(void);
int test_parse_config_invalid_cache_timeout	(void);

int test_parse_config_valid_default_profile	(void);

int test_parse_config_no_profiles		(void);
int test_parse_config_one_profile		(void);
int test_parse_config_invalid_profile		(void);
int test_parse_config_multiple_profiles 	(void);
int test_parse_config_same_name_profiles	(void);



//testing get_app_config(char* app_path); Branch Coverage
int test_global_app_config_no (void);
int test_global_app_config_yes (void);
int test_default_app_config (void);



int test_parse_config_no_file			(void){
	if(parse_config(NULL) != -1) return FAIL;
	if(get_app_config(NULL) != NULL) return FAIL;
	return PASS;
}

int test_parse_config_no_validation		(void){
	return PASS;
}

int test_parse_config_no_app_custom		(void){
	return PASS;

}

int test_parse_config_no_trust_store		(void){
	return PASS;
}

int test_parse_config_no_min_protocol		(void){
	return PASS;
}

int test_parse_config_no_cipher_suite		(void){
	return PASS;
}

int test_parse_config_no_cache_timeout		(void){
	return PASS;
}

int test_parse_config_invalid_file		(void){
	return PASS;
}

int test_parse_config_invalid_validation	(void){
	return PASS;
}
	
int test_parse_config_invalid_app_custom	(void){
	return PASS;
}
	
int test_parse_config_invalid_trust_store	(void){
	return PASS;
}
	
int test_parse_config_invalid_min_protocol	(void){
	return PASS;
}
	
int test_parse_config_invalid_max_protocol	(void){
	return PASS;
}
	
int test_parse_config_invalid_cipher_suite	(void){
	return PASS;
}
	
int test_parse_config_invalid_cache_timeout	(void){
	return PASS;
}

int test_parse_config_valid_default_profile	(void){
	ssa_config_t* ssa_cfg;
	if(parse_config(VALID_FILE) != 3) return FAIL;
	if( (ssa_cfg = get_app_config(NULL)) == NULL) return FAIL;
	return PASS;
}

int test_parse_config_no_profiles		(void){
	if(parse_config(NO_PROFILES) != 1) return FAIL;
	return PASS;
}
	
int test_parse_config_one_profile		(void){
	if(parse_config(ONE_PROFILE) != 2) return FAIL;
	return PASS;
}
	
int test_parse_config_invalid_profile		(void){
	return PASS;
}
	
int test_parse_config_multiple_profiles 	(void){
	if(parse_config(VALID_FILE) != 3) return FAIL;
	return PASS;
}
	
int test_parse_config_same_name_profiles	(void){
	return PASS;
}



//testing get_app_config(char* app_path); Branch Coverage
int test_global_app_config_no (void){
	parse_config(VALID_FILE);
	if( get_app_config("/fake/path") != get_app_config(NULL)) return FAIL;
	return PASS;
}

int test_global_app_config_yes (void){
	parse_config(VALID_FILE);
	if( get_app_config("/bin/ncat") == get_app_config(NULL)) return FAIL;
	return PASS;
}

int test_default_app_config (void){
	parse_config(VALID_FILE);
	if(get_app_config(NULL) == NULL) return FAIL;
	return PASS;
}

void run_tests(test_t* tests, size_t num_tests) {
	char buf[BUFFER_SIZE];
	int ret;
	int i;
	int len;
	int passed_tests = 0;
	printf("Starting Tests\n");
	printf("********************************************************************************\n");
	for (i = 0 ; i < num_tests ; i++ ){
		ret = (*tests[i].func)();
		len = strlen(tests[i].name);	
		strcpy(buf,tests[i].name);
		memset(&buf[len],'.',RESULT_POSITION-len);
		strcpy(&buf[RESULT_POSITION],ret ? PASSED_TEST :FAILED_TEST);
		printf("%s\n", buf);
		passed_tests+= ret;
	}
	printf("********************************************************************************\n\n");
	printf("PASSED %d/%ld tests\n\n", passed_tests, num_tests);
}

#define SIZE_OF_TEST_ARRAY 8

int main(int argc, char* argv[]){
	test_t test_array[SIZE_OF_TEST_ARRAY] = 
	{ 
		{test_parse_config_no_file, "NO FILE"},
		{test_parse_config_valid_default_profile,"VALID DEFAULT PROFILE"},
		{test_parse_config_no_profiles, "NO PROFILES"},
		{test_parse_config_one_profile, "ONE PROFILE"},
		{test_parse_config_multiple_profiles, "MULTIPLE PROFILES"},
		{test_default_app_config, "RETRIEVE DEFAULT PROFILE"},
		{test_global_app_config_yes,"RETRIEVE VALID APP PROFILE"},
		{test_global_app_config_no,"FAKE PROFILE RETURNS DEFAULT"}
       	};
	run_tests(test_array,SIZE_OF_TEST_ARRAY);
	return 0;
}



