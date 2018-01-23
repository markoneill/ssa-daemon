#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <sys/signal.h>
#include <netdb.h>
#include <pthread.h>
#include "../../socktls.h"

typedef struct param {
	int id; /* thread ID */
	/* add other things here as needed */
} param_t;

int connect_to_host(char* host, char* service);
void * threaded_connection();
void recv_func(int sock_fd,char* http_response);
void send_func(int sock_fd, char* http_request,int len);
int const CALLS_PER_THREAD = 1;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t	cond = PTHREAD_COND_INITIALIZER;

int const NUM_THREADS = 50;
int readyCount;
int main() {
	int i;
	readyCount = 0;
	pthread_t t[NUM_THREADS];
	param_t t_params[NUM_THREADS];
	FILE *fp;
	time_t before, after;
	fp=fopen("stats.csv","a");
	struct timeval tv;
	//fprintf(fp,"numThreads,callsPerThread, time, ave/per thread");
	signal(SIGPIPE, SIG_IGN); /* Non-portable but I don't care right now */
	gettimeofday(&tv,NULL);
	before = tv.tv_usec;
	for(i = 0; i < NUM_THREADS ; i++) {
		t_params[i].id = i;
		pthread_create(&t[i], NULL, threaded_connection, (void*)&t_params[i]);
	}
	for(i = 0; i < NUM_THREADS; i++) {
		pthread_join(t[i],NULL);
	}
	gettimeofday(&tv,NULL);
	after = tv.tv_usec;
	fprintf(fp, "\n%d,%d,%lu,%lu",NUM_THREADS,CALLS_PER_THREAD,(after-before), (after-before)/NUM_THREADS);
	fclose(fp);
	return 0;
}

void * threaded_connection(void* arg) {
	int i;
	int sock_fd;
	int thread_id;
	param_t* params = (param_t*)arg;
	char http_response[2048];
	char http_request[] = "GET / HTTP/1.1\r\nHost: www.phoenixteam.net\r\n\r\n";
	thread_id = params->id;
	sock_fd = connect_to_host("192.168.21.101", "8888");
	
	memset(http_response, 0, 2048);
	for(i = 0; i < CALLS_PER_THREAD; i++) {
		//send(sock_fd, http_request,sizeof(http_request)-1,0);
		while(recv(sock_fd, http_response,750,0));
		//printf("Iteration %d completed for thread ID %d\n", i, thread_id);
		//printf("Received:\n%s", http_response);
	}
	printf("Thread %d finished %d iterations\n", thread_id, i);
	close(sock_fd);
	
	return NULL;
}

void send_func(int sock_fd, char* http_request,int len) {
	send(sock_fd, http_request, len, 0);
}
void recv_func(int sock_fd,char* http_response){
    recv(sock_fd, http_response, 750, 0); /* Just grab up to the first 750 bytes from the host (for now) */
}
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
		exit(EXIT_FAILURE);
	}
	
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
	        if (setsockopt(sock, IPPROTO_TLS, SO_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: SO_HOSTNAME");
			close(sock);
			continue;
		}
		pthread_mutex_lock(&lock);
		readyCount++;
		while(!(readyCount == NUM_THREADS)){
		 	pthread_cond_wait(&cond,&lock);
		}
		pthread_mutex_unlock(&lock);
		pthread_cond_signal(&cond);
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
		exit(EXIT_FAILURE);
	}
	return sock;
}
