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
#include "utils.h"
#include "../../in_tls.h"

#define CLIENT_READY_NAME "/clientreadysem"
#define SERVER_READY_NAME "/serverreadysem"
#define SERVER_LISTEN_NAME "/serverlistensem"
#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."


#define NUM_TESTS 9

/* initialization */
void run_as_server(test_funct_t start_funk);
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
int send_recv_test_client(void);
int send_recv_test_server(void);
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
			{ {connect_test_client, "connect test"},
			  {send_recv_test_client, "send recev test"},
			  {hostname_test_client, "hostname test"},
			  {certificate_test_client, "certificate test"},
			  {ttl_test_client, "ttl test"},
			  {disable_cipher_test_client, "disable cipher test"},
			  {peer_identity_test_client, "peer identity test"},
			  {request_peer_auth_test_client, "request peer auth test"},
			  {upgrade_test_client, "upgrade test"} };

	client_init();
	run_tests("tls options test", tests, NUM_TESTS);
	client_destroy();
	return 0;
}

void run_as_server(test_funct_t start_func) {
	status = PASS;
	if (!(server_pid = fork())) {
		if ((server_listens_sem = sem_open(SERVER_LISTEN_NAME, 0)) == SEM_FAILED) {
			perror("run_as_server");
		}
		if ((server_ready_sem = sem_open(SERVER_READY_NAME, 0)) == SEM_FAILED) {
			perror("run_as_server");
		}
		if ((client_ready_sem = sem_open(CLIENT_READY_NAME, 0)) == SEM_FAILED) {
			perror("run_as_server");
		}
		(*start_func)();
		server_destroy();
		exit(EXIT_SUCCESS);
	}
	sleep(.2);
	sem_wait(server_listens_sem);
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
		perror("client_destroy: sem_close");
	}
	if (sem_close(server_listens_sem)) {
		perror("client_destroy: sem_close");
	}
	if (sem_close(client_ready_sem)) {
		perror("client_destroy: sem_close");
	}
	if (sem_unlink(SERVER_READY_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	if (sem_unlink(SERVER_LISTEN_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	if (sem_unlink(CLIENT_READY_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	return;
}

int connect_test_client(void) {
	char buff[LARGE_BUFFER];
	int sock;
	int ret;

	ret = PASS;
	run_as_server(connect_test_server);
	strncpy(buff, LOREM_IPSUM, LARGE_BUFFER);

	sock = connect_to_host("localhost","8080");
	if ( sock == -1){
		return FAIL;
	}
	if ((ret = send(sock, buff, strlen(buff), 0)) == -1) {
		ret = FAIL;
	}
	else if ((ret = recv(sock, buff, LARGE_BUFFER, 0)) == -1) {
		ret = FAIL;
	}
	
	if (close(sock) == -1) {
		perror("connect_test_client close");
	}

	return ret && status ? PASS : FAIL;
}

int connect_test_server(void) {
	int c_fd;
	int listen_fd;
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);

	listen_fd = bind_listen(8080, "localhost");
	sem_post(server_listens_sem);
	c_fd = accept(listen_fd, (struct sockaddr*)&s_addr, &addr_len);
	echo_recv(c_fd, NULL, 0);
	if (close(c_fd) == -1) {
		perror("close connect_test_server");
	}

	return PASS;
}

int send_recv_test_client(void) {
	return FAIL;
}

int send_recv_test_server(void) {
	return FAIL;
}

int hostname_test_client(void) {
	return FAIL;
}

int hostname_test_server(void) {
	int c_fd;
	int listen_fd;
	int ret;
	char servername[255];
	socklen_t servername_len = sizeof(servername);
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);

	ret = PASS;
	listen_fd = bind_listen(8080, "localhost");
	sem_post(server_listens_sem);
	
	c_fd = accept(listen_fd, (struct sockaddr*)&s_addr, &addr_len);
	if (getsockopt(c_fd, IPPROTO_TLS, TLS_HOSTNAME, servername, &servername_len) == -1) {
		perror("getsockopt: TLS_HOSTNAME");
		ret = FAIL;
	}
	else if (strcmp(servername,"localhost") != 0) {
		ret = FAIL;
	}

	echo_recv(c_fd, NULL, 0);
	if (close(c_fd) == -1) {
		perror("close connect_test_server");
	}

	return ret && status ? PASS : FAIL;
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
