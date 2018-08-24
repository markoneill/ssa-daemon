
/* This test creates a client and a server, to test the configure file options for the SSA-daemon.
 * It forks a server to listen for incomming connections and evaluate them for
 * corectness. If the ssa does not behave as expected the server will exit with
 * a non-zero return code and the sigchild handler will be called notifying
 * the test program that an error was discovered. The state of the program
 * may then be printed before termination, or logged depending on future
 * implementation decisions.
 */

#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include "../../in_tls.h"
#include "../../config.h"

#define CERT_FILE_A	"../certificate_a.pem"
#define KEY_FILE_A	"../key_a.pem"
#define CERT_FILE_B	"../certificate_b.pem"
#define KEY_FILE_B	"../key_b.pem"
#define NO_APP_CUSTOM		"cfgFiles/no_app_custom.cfg"
#define NO_CACHE_TIMEOUT	"cfgFiles/no_cache_timeout.cfg"
#define NO_CIPHER_SUITE		"cfgFiles/no_cipher_suite.cfg"
#define NO_MIN_PROTOCOL 	"cfgFiles/no_min_protocol.cfg"
#define NO_PROFILES		"cfgFiles/no_profiles.cfg"
#define NO_TRUST_STORE	 	"cfgFiles/no_trust_store.cfg"
#define NO_VALIDATION		"cfgFiles/no_validation.cfg"
#define ONE_PROFILE	 	"cfgFiles/one_profile.cfg"
#define VALID_FILE		"cfgFiles/vaild.cfg"
#define a	"cfgFiles/.cfg"
#define b	"cfgFiles/.cfg"
#define c	"cfgFiles/.cfg"
#define d	"cfgFiles/.cfg"
#define e	"cfgFiles/.cfg"
#define BUFFER_SIZE	2048

#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

#define PASS 1
#define FAIL 0

typedef int (*test_funct_t)(void);
typedef struct {
	test_funct_t func;
	char* name;
}test_t;

/* test functions */
void run_config_parsing_test (void);


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

// testing


/* signal handlers */
void client_sigchld_handler (int signal);

/* globals */
sem_t client_ready_sem;
sem_t server_ready_sem;
sem_t server_listens_sem;
int status;


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
int test_parse_config_invalid_cache_timeout	(void){i
	return PASS;
}

int test_parse_config_valid_default_profile	(void){
	if(parse_config(VALID_FILE) != 2) return FAIL;
	if(get_default_config() == NULL) return FAIL;
	return PASS;
	
}

int test_parse_config_no_profiles		(void){
	return PASS;
}
int test_parse_config_one_profile		(void){
	return PASS;
}
int test_parse_config_invalid_profile		(void){
	return PASS;
}
int test_parse_config_multiple_profiles 	(void){
	return PASS;
}
int test_parse_config_same_name_profiles	(void){
	return PASS;
}



//testing get_app_config(char* app_path); Branch Coverage
int test_global_app_config_no (void){
	return PASS;
}
int test_global_app_config_yes (void){
	return PASS;
}
int test_default_app_config (void){
	return PASS;
}






#define SIZE_OF_TEST_ARRAY 1

int main(int argc, char* argv[]){
	test_t test_array[SIZE_OF_TEST_ARRAY] = { {test_parse_config_valid_default_profile,"VAILD DEFAULT PROFILE"} }
	int passed_tests = 0;
	int i;
	for (i = 0 ; i < SIZE_OF_TEST_ARRAY ; i++ ){
		passed+= (*test_array[i])();
	}
	printf("Passed %d/%d tests", passed_tests, SIZE_OF_TEST_ARRAY);

}


