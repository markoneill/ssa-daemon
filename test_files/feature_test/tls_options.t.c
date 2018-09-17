/* This test creates a client and a server, to test a varioty of TLS options.
 * It forks a server to listen for incomming connections and evaluate them for
 * corectness. If the ssa does not behave as expected the server will exit with
 * a non-zero return code and the sigchild handler will be called noatifying
 * the test program that an error was discovered. The state of the program
 * may then be printed before termination, or loged depending on future
 * implementation desisions.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test_view.h"
#include "utils.h"
#include "../../in_tls.h"

#define CLIENT_READY_NAME	"/clientreadysem"
#define SERVER_READY_NAME	"/serverreadysem"
#define CONTEX_LOCK_NAME	"/contentlocksem"
#define LOREM_IPSUM "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
#define MIN(a,b) a < b ? a : b

#define PENDING		       -1
#define DONE			0
#define RUNNING			1
#define WAIT_TIMEOUT_SEC	2
#define NUM_TESTS		9
#define MILL		     1000
#define SERVER_START_PORT    8080

/* initialization */
int run_on_server(test_funct_t start_funk);
void server_fork(void);
void server_main(void);
int server_init(void);
void server_destroy(void);
void client_init(void);
void client_destroy(void);
int wait_server_response(time_t sec);

/* context minipulating */
test_funct_t get_server_function(void);
void set_server_function(test_funct_t);
int  get_test_status(void);
void set_test_status(int);
int  get_test_ret_val(void);
void set_test_ret_val(int);

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
void sigusr1_handler(int signal);
void server_sigalrm_handler(int signal);

/* local typedefs */
typedef struct test_ctx {
	test_funct_t server_funct;
	int server_port;
	int funct_ret;
	int test_status;
} test_ctx_t;

/* globals */
test_ctx_t* ctx;
sem_t* client_ready_sem;
sem_t* server_ready_sem;
sem_t* context_lock_sem;
struct pollfd listen_fd;
int server_pid;


int main(int argc, char* argv[]) {
	test_t tests[NUM_TESTS] =
			{
			  {connect_test_client, "connect test"},
			  {send_recv_test_client, "send recev test"},
			  {hostname_test_client, "hostname test"},
			  {certificate_test_client, "certificate test"},
			  {ttl_test_client, "ttl test"},
			  {disable_cipher_test_client, "disable cipher test"},
			  {peer_identity_test_client, "peer identity test"},
			  {request_peer_auth_test_client, "request peer auth test"},
			  {upgrade_test_client, "upgrade test"} };
	ctx = (test_ctx_t*) mmap(NULL, sizeof(test_ctx_t), PROT_READ |
			PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
	client_init();
	server_fork();
	printf("session pids: client %d, server %d\n", getpid(), server_pid);
	run_tests("tls options test", tests, NUM_TESTS);
	client_destroy();
	set_test_status(DONE);
	while (server_pid) {
		sleep(.5);
	}
	return 0;
}

test_funct_t get_server_function(void) {
	test_funct_t test;
	printf("server function retrieved\n");
	//sem_wait(context_lock_sem);
	test = ctx->server_funct;
	//sem_post(context_lock_sem);
	return test;
}

void set_server_function(test_funct_t funct) {
	//sem_wait(context_lock_sem);
	ctx->server_funct = funct;
	printf("context changed: funct %p, ret %s%s%s, stat %d\n",
			ctx->server_funct,
			ctx->funct_ret == PENDING ? "PENDING" : "",
			ctx->funct_ret == FAIL ? "FAIL" : "",
			ctx->funct_ret == PASS ? "PASS" : "",
			ctx->test_status);//*/
	//sem_post(context_lock_sem);
}

int get_server_port(void) {
	int port;
	//sem_wait(context_lock_sem);
	port = ctx->server_port;
	//sem_post(context_lock_sem);
	return port;
}

void set_server_port(int port) {
	//sem_wait(context_lock_sem);
	ctx->server_port = port;
	//sem_post(context_lock_sem);
}

int get_test_status(void) {
	int status;
	printf("test status retrieved\n");
	//sem_wait(context_lock_sem);
	status = ctx->test_status;
	//sem_post(context_lock_sem);
	return status;
}

void set_test_status(int status) {
	//sem_wait(context_lock_sem);
	ctx->test_status = status;
	printf("context changed: funct %p, ret %s%s%s, stat %d\n",
			ctx->server_funct,
			ctx->funct_ret == PENDING ? "PENDING" : "",
			ctx->funct_ret == FAIL ? "FAIL" : "",
			ctx->funct_ret == PASS ? "PASS" : "",
			ctx->test_status);//*/
	//sem_post(context_lock_sem);
}

int get_test_ret_val(void) {
	int ret_val;
	//sem_wait(context_lock_sem);
	ret_val = ctx->funct_ret;
	printf("test ret val (%s%s%s) retrieved\n",
			ctx->funct_ret == PENDING ? "PENDING" : "",
			ctx->funct_ret == FAIL ? "FAIL" : "",
			ctx->funct_ret == PASS ? "PASS" : "");//*/
	//sem_post(context_lock_sem);
	return ret_val;
}

void set_test_ret_val(int val) {
	//sem_wait(context_lock_sem);
	ctx->funct_ret = val;
	printf("context changed: funct %p, ret %s%s%s, stat %d\n",
			ctx->server_funct,
			ctx->funct_ret == PENDING ? "PENDING" : "",
			ctx->funct_ret == FAIL ? "FAIL" : "",
			ctx->funct_ret == PASS ? "PASS" : "",
			ctx->test_status);//*/
	//sem_post(context_lock_sem);
}

int run_on_server(test_funct_t start_func) {
	struct timespec ts;

	if (get_test_status() != RUNNING) {
		fprintf(stderr, "server not active\n");
		return -1;
	}
	set_server_function(start_func);
	set_test_ret_val(PENDING);
	if (sem_post(client_ready_sem) == -1) {
		perror("run_on_server sem_post");
	}
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		perror("server_main clock_gettime");
	}
	ts.tv_sec += WAIT_TIMEOUT_SEC;
	if (sem_timedwait(server_ready_sem, &ts) == -1) {
		perror("run_on_server sem_wait");
		return -1;
	}
	return 0;
}

void server_fork(void) {
	int ret;
	set_test_status(RUNNING);
	if (!(server_pid = fork())) {
		ret = server_init();
		sem_post(server_ready_sem);
		if (ret == -1) {
			set_test_status(DONE);
		}
		else {
			server_main();
		}
		server_destroy();
		exit(EXIT_SUCCESS);
	}
	sem_wait(server_ready_sem);
	return;
}

void server_main(void) {
	test_funct_t start_func;
	struct timespec ts;

	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("server_main clock_gettime");
		}
		ts.tv_sec += WAIT_TIMEOUT_SEC;

		if (sem_timedwait(client_ready_sem, &ts) == -1) {
			if (get_test_status() == DONE) {
				break;
			}
			continue;
		}
		start_func = get_server_function();
		if (sem_post(server_ready_sem) == -1) {
			perror("server_main sem_post");
		}
		set_test_ret_val((*start_func)());
	}
}

int server_init(void) {
	int port;
	int i = 0;

	/* set signal handlers */
	if (signal(SIGUSR1, sigusr1_handler) == SIG_ERR) {
		perror("server_init signal");
		return -1;
	}
	if (signal(SIGALRM, server_sigalrm_handler) == SIG_ERR) {
		perror("server_init signal");
		return -1;
	}

	/* open semaphores */
	if ((server_ready_sem = sem_open(SERVER_READY_NAME, 0)) == SEM_FAILED) {
		perror("server_init sem_open");
		return -1;
	}
	if ((client_ready_sem = sem_open(CLIENT_READY_NAME, 0)) == SEM_FAILED) {
		perror("server_init sem_open");
		return -1;
	}
	if ((context_lock_sem = sem_open(CONTEX_LOCK_NAME, 1)) == SEM_FAILED) {
		perror("server_init sem_open");
		return -1;
	}

	/* open listening fd */
	listen_fd.fd = -1;
	while (listen_fd.fd < 0) {
		port = i + SERVER_START_PORT;
		listen_fd.fd = bind_listen(port, "localhost");
		if (errno != EADDRINUSE)
			break;
		i++;
	}
	set_server_port(port);
	if (listen_fd.fd == -1) return -1;
	listen_fd.events = POLLIN;
	return 0;
}

void server_destroy(void) {
	if (close(listen_fd.fd) == -1) {
		perror("server_destroy close");
	}
	if (sem_close(server_ready_sem)) {
		perror("server_destroy sem_close");
	}
	if (sem_close(client_ready_sem)) {
		perror("server_destroy sem_close");
	}
	if (sem_close(context_lock_sem)) {
		perror("server_destroy sem_close");
	}
	return;
}

void client_init(void) {
	if ((server_ready_sem = sem_open(SERVER_READY_NAME, O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("client_init");
	}
	if ((client_ready_sem = sem_open(CLIENT_READY_NAME, O_CREAT, 0644, 0)) == SEM_FAILED) {
		perror("client_init");
	}
	if ((context_lock_sem = sem_open(CONTEX_LOCK_NAME, O_CREAT, 0644, 1)) == SEM_FAILED) {
		perror("client_init");
	}
	if (signal(SIGCHLD, client_sigchld_handler) == SIG_ERR) {
		perror("client_init signal");
	}
	return;
}

void client_destroy(void) {
	fflush(stdout);
	if (sem_close(server_ready_sem)) {
		perror("client_destroy: sem_close");
	}
	if (sem_close(client_ready_sem)) {
		perror("client_destroy: sem_close");
	}
	if (sem_close(context_lock_sem)) {
		perror("client_destroy: sem_close");
	}
	if (sem_unlink(CONTEX_LOCK_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	if (sem_unlink(SERVER_READY_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	if (sem_unlink(CLIENT_READY_NAME)) {
		perror("client_destroy: sem_unlink");
	}
	return;
}

int wait_server_response(time_t sec) {
	struct timeval tv = {0, 0};
	struct timeval step = {0, 200000};
	int ret_val = PENDING;

	printf("start wait\n"); fflush(stdout);
	tv.tv_sec = sec;
	while (timercmp(&tv, &step, >)) {
		if (!server_pid) {
			printf("server exited\n"); fflush(stdout);
			break;
		}
		if ((ret_val = get_test_ret_val()) != PENDING) {
			printf("server finished. code=%d\n", ret_val); fflush(stdout);
			break;
		}
		timersub(&tv, &step, &tv);
		sleep(.2);
	}
	printf("stop wait\n"); fflush(stdout);
	return ret_val;
}

int connect_test_client(void) {
	char port[6];
	int client_ret;
	int server_ret;
	int sock;

	client_ret = PASS;
	if (run_on_server(connect_test_server) == -1) {
		fprintf(stderr, "connect_test_client run_on_server\n");
		return FAIL;
	}

	sprintf(port, "%d", get_server_port());
	sock = connect_to_host("localhost", port);
	if ( sock == -1){
		perror("connect_test_client sock");
		return FAIL;
	}
	if (close(sock) == -1) {
		perror("connect_test_client close");
	}
	server_ret = wait_server_response(20);
	return client_ret && server_ret ? PASS : FAIL;
}

int connect_test_server(void) {
	int ret;
	int c_fd;
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);

	if (listen_fd.fd == -1) {
		return FAIL;
	}
	ret = poll(&listen_fd, 1, WAIT_TIMEOUT_SEC*MILL);
	if (ret == -1) {
		perror("connect_test_server poll");
		return FAIL;
	}
	if (ret == 0) {
		fprintf(stderr, "connect_test_server: poll: timed out\n");
		return FAIL;
	}
	c_fd = accept(listen_fd.fd, (struct sockaddr*)&s_addr, &addr_len);
	if (close(c_fd) == -1) {
		perror("close connect_test_server");
	}
	return PASS;
}

int send_recv_test_client(void) {
	struct timeval tv = { 5, 0 };
	char buff[LARGE_BUFFER];
	char port[6];
	int client_ret;
	int server_ret;
	int sock;

	client_ret = PASS;
	if (run_on_server(send_recv_test_server) == -1) {
		fprintf(stderr, "connect_test_client run_on_server\n");
		return FAIL;
	}
	strncpy(buff, LOREM_IPSUM, strlen(LOREM_IPSUM)+1);

	sprintf(port, "%d", get_server_port());
	sock = connect_to_host("localhost", port);
	if ( sock == -1){
		perror("send_recv_test_client sock");
		return FAIL;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_SNDTIMEO");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_RCVTIMEO");
	}
	if ((client_ret = send(sock, buff, strlen(buff)+1, 0)) == -1) {
		perror("send_recv_test_client send");
		client_ret = FAIL;
	}
	if ((client_ret = recv(sock, buff, LARGE_BUFFER, 0)) == -1) {
		perror("send_recv_test_client recv");
		client_ret = FAIL;
	}
	if (strcmp(buff, LOREM_IPSUM) != 0) {
		fprintf(stderr, "send_recv_test_client error: coruption\n");
		client_ret = FAIL;
	}
	printf("client transaction %s\n", client_ret ? "finished" : "failed"); fflush(stdout);
	
	if (close(sock) == -1) {
		perror("connect_test_client close");
	}

	server_ret = wait_server_response(10);

	return client_ret && server_ret ? PASS : FAIL;
}

int send_recv_test_server(void) {
	int c_fd;
	int ret;
	int request_len;
	char buff[LARGE_BUFFER];
	struct timeval tv = { 5, 0 };
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);

	ret = PASS;
	if (listen_fd.fd == -1) {
		return FAIL;
	}
	ret = poll(&listen_fd, 1, WAIT_TIMEOUT_SEC*MILL);
	if (ret == -1) {
		perror("connect_test_server poll");
		return FAIL;
	}
	if (ret == 0) {
		fprintf(stderr, "connect_test_server: poll: timed out\n");
		return FAIL;
	}
	c_fd = accept(listen_fd.fd, (struct sockaddr*)&s_addr, &addr_len);
	if (setsockopt(c_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_RCVTIMEO");
	}
	if (setsockopt(c_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_SNDTIMEO");
	}
	if ((request_len = recv(c_fd, buff, LARGE_BUFFER, 0)) == -1) {
		perror("send_recv_test_server recv");
		ret = FAIL;
	}
	if ((send(c_fd, buff, request_len, 0)) == -1) {
		perror("send_recv_test_server send");
		ret = FAIL;
	}
	if (strncmp(buff, LOREM_IPSUM, MIN(strlen(LOREM_IPSUM), request_len)) != 0) {
		fprintf(stderr, "send_recv_test_server error: coruption\n\n\"%s\" reported as \n\n\"%s\"\n", LOREM_IPSUM, buff);
		ret = FAIL;
	}
	printf("server transaction %s\n", ret ? "finished" : "failed"); fflush(stdout);

	if (close(c_fd) == -1) {
		perror("close connect_test_server");
	}
	return ret;
}

int hostname_test_client(void) {
	struct timeval tv = { 5, 0 };
	char buff[LARGE_BUFFER];
	char port[6];
	int client_ret;
	int server_ret;
	int sock;

	client_ret = PASS;
	if (run_on_server(hostname_test_server) == -1) {
		fprintf(stderr, "connect_test_client run_on_server\n");
		return FAIL;
	}
	strncpy(buff, LOREM_IPSUM, LARGE_BUFFER);

	sprintf(port, "%d", get_server_port());
	sock = connect_to_host("localhost", port);
	if ( sock == -1){
		return FAIL;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_SNDTIMEO");
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
		perror("setsockopt SO_RCVTIMEO");
	}
	if ((client_ret = send(sock, buff, strlen(buff), 0)) == -1) {
		client_ret = FAIL;
	}
	if ((client_ret = recv(sock, buff, LARGE_BUFFER, 0)) == -1) {
		client_ret = FAIL;
	}

	if (close(sock) == -1) {
		perror("connect_test_client close");
	}

	server_ret = wait_server_response(10);

	return client_ret && server_ret ? PASS : FAIL;
}

int hostname_test_server(void) {
	int ret;
	int c_fd;
	char servername[255];
	socklen_t servername_len = sizeof(servername);
	struct sockaddr_storage s_addr;
	socklen_t addr_len = sizeof(s_addr);

	ret = poll(&listen_fd, 1, WAIT_TIMEOUT_SEC*MILL);
	if (ret == -1) {
		perror("connect_test_server poll");
		return FAIL;
	}
	if (ret == 0) {
		fprintf(stderr, "connect_test_server: poll: timed out\n");
		return FAIL;
	}
	printf("poll returned with action %s%s%s%s%s\n",
			listen_fd.revents & POLLIN ? "POLLIN": "",
			listen_fd.revents & POLLOUT ? "POLLOUT": "",
			listen_fd.revents & POLLERR ? "POLLERR": "",
			listen_fd.revents & POLLHUP ? "POLLHUP": "",
			listen_fd.revents & POLLNVAL ? "POLLNVAL": "");
	ret = PASS;
	c_fd = accept(listen_fd.fd, (struct sockaddr*)&s_addr, &addr_len);
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
	return ret ? PASS : FAIL;
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
			ctx->funct_ret = FAIL;
			ctx->test_status = DONE;
			return;
		}
	}
	return;
}

void sigusr1_handler(int signal) {
	ctx->test_status = DONE;
}

void server_sigalrm_handler(int signal) {
	return;
}
