/* This test creates a client and a server, to test a varioty of TLS options.
 * It forks a server to listen for incomming connections and evaluate them for
 * corectness. If the ssa does not behave as expected the server will exit with
 * a non-zero return code and the sigchild handler will be called noatifying
 * the test program that an error was discovered. The state of the program
 * may then be printed before termination, or loged depending on future
 * implementation desisions.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include "test_view.h"
#include "../../in_tls.h"

#define CERT_FILE_A	"../certificate_a.pem"
#define KEY_FILE_A	"../key_a.pem"
#define CERT_FILE_B	"../certificate_b.pem"
#define KEY_FILE_B	"../key_b.pem"
#define MY_BUFFER_SIZE	2048

#define CLIENT_READY_NAME "/clientreadysem"
#define SERVER_READY_NAME "/serverreadysem"
#define SERVER_LISTEN_NAME "/serverlistensem"
#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."


#define NUM_TESTS 8

/* initialization */
void server_init(test_funct_t start_funk);
void server_destroy(void);
void client_init(void);
void client_destroy(void);

/* test functions */
/*
void run_option_tests_client(int* server_pid, test_t* tests, int num);
void run_option_tests_server(test_t* tests, int num, test_funct_t start_func);
*/
int connect_test_client(void);
int connect_test_server(void);
int hostname_test_client(void);
int hostname_test_server(void);
int certificate_test_client(void);
int certificate_test_server(void);
int ttl_test_client(void);
int ttl_test_server(void);
int disable_cipher_test_client(void);
int disable_cipher_test_server(void);
int peer_identity_test_client(void);
int peer_identity_test_server(void);
int request_peer_auth_test_client(void);
int request_peer_auth_test_server(void);
int upgrade_test_client(void);
int upgrade_test_server(void);

/* signal handlers */
void client_sigchld_handler(int signal);

/* globals */
sem_t* client_ready_sem;
sem_t* server_ready_sem;
sem_t* server_listens_sem;
int server_pid;
volatile int status;


int main(int argc, char* argv[]) {
	test_t tests[NUM_TESTS] =
			{
			  {connect_test_client, "connect_test_server"},
			  {hostname_test_client, "hostname_test_server"},
			  {certificate_test_client, "certificate_test_server"},
			  {ttl_test_client, "ttl_test_server"},
			  {disable_cipher_test_client, "disable_cipher_test_server"},
			  {peer_identity_test_client, "peer_identity_test_server"},
			  {request_peer_auth_test_client, "request_peer_auth_test_server"},
			  {upgrade_test_client, "upgrade_test_server"} };

/*	if (argc < 2) {
	printf("usage: %s <host name>\n", argv[0]);
	return 0;
	}
 */

	client_init();
	run_tests("tls options test", tests, NUM_TESTS);
	client_destroy();
	return 0;
}

void server_init(test_funct_t start_func) {
	if (!(server_pid = fork())) {
		if ((server_listens_sem = sem_open(SERVER_LISTEN_NAME, 0)) == SEM_FAILED) {
			perror("server_init");
		}
		if ((server_ready_sem = sem_open(SERVER_READY_NAME, 0)) == SEM_FAILED) {
			perror("server_init");
		}
		if ((client_ready_sem = sem_open(CLIENT_READY_NAME, 0)) == SEM_FAILED) {
			perror("server_init");
		}
		(*start_func)();
		server_destroy();
		exit(EXIT_SUCCESS);
	}
	return;
}

void server_destroy(void) {
	if (sem_close(server_ready_sem)) {
		perror("server_destroy");
	}
	if (sem_close(server_listens_sem)) {
		perror("server_destroy");
	}
	if (sem_close(client_ready_sem)) {
		perror("server_destroy");
	}
	return;
}

void client_init(void) {
	if ((server_listens_sem = sem_open(SERVER_LISTEN_NAME, O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("client_init");
	}
	if ((server_ready_sem = sem_open(SERVER_READY_NAME, O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("client_init");
	}
	if ((client_ready_sem = sem_open(CLIENT_READY_NAME, O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("client_init");
	}
	signal(SIGCHLD, client_sigchld_handler);
	printf("client ready\n");
	return;
}

void client_destroy(void) {
	printf("destroy client\n");
	fflush(stdout);
	if (sem_close(server_ready_sem)) {
		perror("client_destroy");
	}
	if (sem_close(server_listens_sem)) {
		perror("client_destroy");
	}
	if (sem_close(client_ready_sem)) {
		perror("client_destroy");
	}
	if (sem_unlink(SERVER_READY_NAME)) {
		perror("client_destroy");
	}
	if (sem_unlink(SERVER_LISTEN_NAME)) {
		perror("client_destroy");
	}
	if (sem_unlink(CLIENT_READY_NAME)) {
		perror("client_destroy");
	}
	if (server_pid) {
		//kill(- getpid(), SIGINT);
		server_pid = 0;
	}
	return;
}

/*
void run_option_tests_client(int* server_pid, test_t* tests, int num) {
	int failcode;
	int i;

	status = PASS;
	for (i = 0; i < num; i++) {
		printf("%s...\n", tests[i].name);
		if (sem_post(client_ready_sem)) { perror("run_option_tests_client post"); }
		if (sem_wait(server_ready_sem)) { perror("run_option_tests_client wait"); }
		failcode = (*(tests[i].client_func))();
		if (~(failcode = failcode || status)) {
			if (tests[i].name) printf("\t\t%s\n", PASSED_TEST);
		}
		else {
			printf("\t\tFAILED (code %d)", -failcode);
			kill(*server_pid, SIGINT);
			status = PASS;
			server_init(tests, tests[i+1].server_func);
		}
	}
}

void run_option_tests_server(test_t* tests, int num, test_funct_t start_func) {
	int failcode;
	int i = 0;

	if (start_func) {
		while (tests[i].server_func != start_func) {
			i++;
			if (i > num) {
				printf("Bad function pointer to server");
				return;
			}
		}
	}

	for (; i < num; i++) {
		if (sem_post(server_ready_sem)) { perror("run_option_tests_server post"); }
		if (sem_wait(client_ready_sem)) { perror("run_option_tests_server wait"); }
		printf("\tserver wait fin\n");
		printf("\tserver starts %s\n", tests[i].name);
		failcode = (*(tests[i].server_func))();
		if (~(failcode = failcode || status)) {
			printf("\t%s compleated\n", tests[i].name);
		}
		else {
			printf("test failed with code %d", -failcode);
			exit(EXIT_FAILURE);
		}
	}
}
*/

int connect_to_host(char* host, char* service) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
	        if (setsockopt(sock, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock);
			continue;
		}

		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock);
			continue;
		}

		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		return -1;
	}
	return sock;
}
int connect_test_client(void) {
	int sock;
	int ret;
	char buff[MY_BUFFER_SIZE];
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	server_init(connect_test_server);

	memset(&addr_list, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	sem_wait(server_listens_sem);
	sock = connect_to_host("localhost","8080");
	if ( sock == -1){
		return FAIL;
	}
	strncpy(buff, LOREM_IPSUM, MY_BUFFER_SIZE);
	if ((ret = send(sock, buff, strlen(buff), 0)) == -1) {
		return FAIL;
	}
	if ((ret = recv(sock, buff, MY_BUFFER_SIZE, 0)) == -1) {
		return FAIL;
	}
	
	close(sock);

	return PASS;
}

int connect_test_server(void) {
	char servername[255];
	socklen_t servername_len = sizeof(servername);
	char request[MY_BUFFER_SIZE];
//	char response[MY_BUFFER_SIZE];
	struct sockaddr_in in_addr;
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);
	int c_fd;

	memset(request, 0, MY_BUFFER_SIZE);

	in_addr.sin_family = AF_INET;
	in_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	in_addr.sin_port = htons(8080);

	int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	bind(fd, (struct sockaddr*)&in_addr, sizeof(in_addr));
	if (setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, CERT_FILE_A, sizeof(CERT_FILE_A)) == -1) {
		perror("cert a");
	}
	if (setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, KEY_FILE_A, sizeof(KEY_FILE_A)) == -1) {
		perror("key a");
	}
	if (setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, CERT_FILE_B, sizeof(CERT_FILE_B)) == -1) {
		perror("cert b");
	}
	if (setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, KEY_FILE_B, sizeof(KEY_FILE_B)) == -1) {
		perror("key b");
	}
	listen(fd, SOMAXCONN);
	printf("server ready\n");
	fflush(stdout);
	sem_post(server_listens_sem);

	c_fd = accept(fd, (struct sockaddr*)&s_addr, &addr_len);
	if (getsockopt(c_fd, IPPROTO_TLS, TLS_HOSTNAME, servername, &servername_len) == -1) {
		perror("getsockopt: TLS_HOSTNAME");
		server_destroy();
		exit(EXIT_FAILURE);
	}
	printf("Client requested host %d %s\n", servername_len,  servername);
	recv(c_fd, request, MY_BUFFER_SIZE, 0);
//	handle_req(request, response);
	send(c_fd, request, MY_BUFFER_SIZE, 0);
	close(c_fd);

	return PASS;
}

int hostname_test_client(void) {
	return FAIL;
}

int hostname_test_server(void) {
	return FAIL;
}

int certificate_test_client(void) {
	return FAIL;
}

int certificate_test_server(void) {
	return FAIL;
}

int ttl_test_client(void) {
	return FAIL;
}

int ttl_test_server(void) {
	return FAIL;
}

int disable_cipher_test_client(void) {
	return FAIL;
}

int disable_cipher_test_server(void) {
	return FAIL;
}

int peer_identity_test_client(void) {
	return FAIL;
}

int peer_identity_test_server(void) {
	return FAIL;
}

int request_peer_auth_test_client(void) {
	return FAIL;
}

int request_peer_auth_test_server(void) {
	return FAIL;
}

int upgrade_test_client(void) {
	return FAIL;
}

int upgrade_test_server(void) {
	return FAIL;
}

void client_sigchld_handler(int signal) {
	int stat;
	waitpid(-1,&stat,0);
	if(WIFEXITED(stat) ) {
		server_pid = 0;
		if( WEXITSTATUS(stat) == EXIT_FAILURE){
			status = FAIL;
			return;
		}
	}
	status = PASS;
	return;
}
