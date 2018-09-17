
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
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>
#include "../../in_tls.h"
#include "../../config.h"
#include "test_view.h"

#define NO_APP_CUSTOM		"cfgFiles/no_app_custom.cfg"
#define NO_CACHE_TIMEOUT	"cfgFiles/no_cache_timeout.cfg"
#define NO_CIPHER_SUITE		"cfgFiles/no_cipher_suite.cfg"
#define NO_MIN_PROTOCOL 	"cfgFiles/no_min_protocol.cfg"
#define NO_PROFILES		"cfgFiles/no_profiles.cfg"
#define NO_TRUST_STORE	 	"cfgFiles/no_trust_store.cfg"
#define NO_VALIDATION		"cfgFiles/no_validation.cfg"
#define ONE_PROFILE	 	"cfgFiles/one_profile.cfg"
#define VALID_FILE		"cfgFiles/valid.cfg"
#define INVALID_MIN_PROTOCOL	"cfgFiles/invalid_min_protocol.cfg"
#define b	"cfgFiles/.cfg"
#define c	"cfgFiles/.cfg"
#define d	"cfgFiles/.cfg"
#define e	"cfgFiles/.cfg"


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

int test_parse_config_exit_failure(char* filename){
	pid_t pid;
	int status;
	if( (pid= fork()) == 0){
		parse_config(filename);
		exit(EXIT_SUCCESS);	
	} else {
		waitpid(pid,&status,0);
		if(WIFEXITED(status) ) {
			if( WEXITSTATUS(status) == EXIT_FAILURE){
				return PASS;
			}
		}
	}
	return FAIL;

}

int test_parse_config_no_file			(void){
	if(parse_config(NULL) != -1) return FAIL;
	if(get_app_config(NULL) != NULL) return FAIL;
	return PASS;
}

int test_parse_config_no_validation		(void){
	return test_parse_config_exit_failure(NO_VALIDATION);
}

int test_parse_config_no_app_custom		(void){
	return test_parse_config_exit_failure(NO_APP_CUSTOM);

}

int test_parse_config_no_trust_store		(void){
	return test_parse_config_exit_failure(NO_TRUST_STORE);
}

int test_parse_config_no_min_protocol		(void){
	return test_parse_config_exit_failure(NO_MIN_PROTOCOL);
}

int test_parse_config_no_cipher_suite		(void){
	return test_parse_config_exit_failure(NO_CIPHER_SUITE);
}

int test_parse_config_no_cache_timeout		(void){
	return test_parse_config_exit_failure(NO_CACHE_TIMEOUT);
}

int test_parse_config_invalid_file		(void){
	return FAIL;
}

int test_parse_config_invalid_validation	(void){
	return FAIL;
}
	
int test_parse_config_invalid_app_custom	(void){
	return FAIL;
}
	
int test_parse_config_invalid_trust_store	(void){
	return FAIL;
}
	
int test_parse_config_invalid_min_protocol	(void){
	return test_parse_config_exit_failure(INVALID_MIN_PROTOCOL);
}
	
int test_parse_config_invalid_max_protocol	(void){
	return FAIL;
}
	
int test_parse_config_invalid_cipher_suite	(void){
	return FAIL;
}
	
int test_parse_config_invalid_cache_timeout	(void){
	return FAIL;
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
	return FAIL;
}
	
int test_parse_config_multiple_profiles 	(void){
	if(parse_config(VALID_FILE) != 3) return FAIL;
	return PASS;
}
	
int test_parse_config_same_name_profiles	(void){
	return FAIL;
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


#define SIZE_OF_TEST_ARRAY 24  

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
		{test_global_app_config_no,"FAKE PROFILE RETURNS DEFAULT"},
		{test_parse_config_same_name_profiles, "SAME NAME PROFILES"},
		{test_parse_config_no_validation, "NO VALIDATION"},
		{test_parse_config_no_app_custom, "NO APP CUSTOM"},
		{test_parse_config_no_trust_store, "NO TRUST STORE"},
		{test_parse_config_no_min_protocol, "NO MIN PROTOCOL"},
		{test_parse_config_no_cipher_suite, "NO CIPHER SUITE"},
		{test_parse_config_no_cache_timeout, "NO CACHE TIMEOUT"},
		{test_parse_config_invalid_file		,"INVAILD FILE"},
		{test_parse_config_invalid_validation	,"INVAILD VALIDATION"},
		{test_parse_config_invalid_app_custom	,"INVAILD APP CUSTOM"},
		{test_parse_config_invalid_trust_store	,"INVAILD TRUST STORE"},
		{test_parse_config_invalid_min_protocol	,"INVAILD MIN PROTOCOL"},
		{test_parse_config_invalid_max_protocol	,"INVAILD MAX PROTOCOL"},
		{test_parse_config_invalid_cipher_suite	,"INVAILD CIPHER SUITE"},
		{test_parse_config_invalid_cache_timeout,"INVAILD CACHE TIMEOUT"},
		{test_parse_config_invalid_profile	,"INVAILD PROFILE"}
       	};
	run_tests("Config File Tests",test_array,SIZE_OF_TEST_ARRAY);
	return 0;
}

