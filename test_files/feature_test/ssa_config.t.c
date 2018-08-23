
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
#define BUFFER_SIZE	2048

#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

#define PASS 0
#define FAIL 1

typedef int (*test_t)(void);

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









int main(int argc, char* argv[]){

 

}


