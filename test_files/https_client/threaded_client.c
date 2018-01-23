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
#include <semaphore.h>
#include <arpa/inet.h>
#include "../../extras/in_tls.h"

typedef struct param {
	int id; /* thread ID */
	int sock;
	/* add other things here as needed */
} param_t;

void* thread_start(void* arg);
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y);

int const CALLS_PER_THREAD = 1;
int const NUM_THREADS = 50;
#define BYTES_TO_FETCH	1000000
#define BUFFER_SIZE	1024

pthread_barrier_t begin_barrier;
pthread_mutex_t	finished_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t finished_sem;
int threads_finished = 0;

int main() {
	int i;
	pthread_t t[NUM_THREADS];
	struct timeval tv_before;
	struct timeval tv_after;
	struct timeval tv_elapsed;
	param_t t_params[NUM_THREADS];
	FILE *fp;

	char host[] = "www.google.com";
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr("127.0.0.1"),
		//.sin_addr.s_addr = inet_addr("192.168.21.101"),
		.sin_port = htons(8888)
	};

	sem_init(&finished_sem, 0, 0);
	fp = fopen("stats.csv", "a");
	fprintf(fp, "numThreads,callsPerThread,timeElapsed\n");
	signal(SIGPIPE, SIG_IGN); /* Non-portable but I don't care right now */
	pthread_barrier_init(&begin_barrier, NULL, NUM_THREADS + 1);

	for (i = 0; i < NUM_THREADS ; i++) {
		t_params[i].id = i;
		t_params[i].sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
		//t_params[i].sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (t_params[i].sock == -1) {
			perror("failed to create a socket");
			exit(EXIT_FAILURE);
		}
	        if (setsockopt(t_params[i].sock, IPPROTO_TLS, SO_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: SO_HOSTNAME");
			exit(EXIT_FAILURE);
		}
		if (connect(t_params[i].sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
			perror("connect");
			exit(EXIT_FAILURE);
		}
		pthread_create(&t[i], NULL, thread_start, (void*)&t_params[i]);
	}

	pthread_barrier_wait(&begin_barrier);
	printf("Threads ready! Start timer!\n");
	gettimeofday(&tv_before, NULL);
	sem_wait(&finished_sem);
	gettimeofday(&tv_after, NULL);
	for(i = 0; i < NUM_THREADS; i++) {
		pthread_join(t[i],NULL);
	}
	if (timeval_subtract(&tv_elapsed, &tv_after, &tv_before) == 1) {
		fprintf(stderr, "Oh no! Difference between after and before was negative!\n");
	}
	fprintf(fp, "%d,%d,%ld.%06ld\n", NUM_THREADS, CALLS_PER_THREAD, tv_elapsed.tv_sec, tv_elapsed.tv_usec);
	fclose(fp);
	return 0;
}

void* thread_start(void* arg) {
	int i;
	int sock_fd;
	int thread_id;
	int bytes_read;
	int total_bytes_read;
	char response[BUFFER_SIZE];

	param_t* params = (param_t*)arg;
	thread_id = params->id;
	sock_fd = params->sock;

	pthread_barrier_wait(&begin_barrier);

	for(i = 0; i < CALLS_PER_THREAD; i++) {
		total_bytes_read = 0;
		while(total_bytes_read < BYTES_TO_FETCH) {
			bytes_read = recv(sock_fd, response, BUFFER_SIZE ,0);
			if (bytes_read == -1) {
				perror("recv");
			}
			else if (bytes_read == 0) {
				printf("Thread ID %d was disconnected\n", thread_id);
			}
			else {
				total_bytes_read += bytes_read;
			}
		}
	}
	printf("Thread %d finished %d iterations\n", thread_id, i);
	pthread_mutex_lock(&finished_lock);
	threads_finished++;
	if (threads_finished == NUM_THREADS) {
		sem_post(&finished_sem);
	}
	pthread_mutex_unlock(&finished_lock);
	return NULL;
}

int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y) {
        struct timeval y_cpy = *y;
        /* Perform the carry for the later subtraction by updating y_cpy. */
        if (x->tv_usec < y_cpy.tv_usec) {
                int nsec = (y_cpy.tv_usec - x->tv_usec) / 1000000 + 1;
                y_cpy.tv_usec -= 1000000 * nsec;
                y_cpy.tv_sec += nsec;
        }
        if (x->tv_usec - y_cpy.tv_usec > 1000000) {
                int nsec = (x->tv_usec - y_cpy.tv_usec) / 1000000;
                y_cpy.tv_usec += 1000000 * nsec;
                y_cpy.tv_sec -= nsec;
        }

        /* Compute the time remaining to wait.
         * tv_usec is certainly positive. */
        result->tv_sec = x->tv_sec - y_cpy.tv_sec;
        result->tv_usec = x->tv_usec - y_cpy.tv_usec;

        /* Return 1 if result is negative. */
        return x->tv_sec < y_cpy.tv_sec;
}
