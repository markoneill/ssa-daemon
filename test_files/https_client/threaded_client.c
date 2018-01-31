#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <getopt.h>
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
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
typedef struct param {
	int id; /* thread ID */
	int sock;
	SSL* ssl;
	/* add other things here as needed */
} param_t;

void* thread_start(void* arg);
int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y);
SSL* openssl_connect_to_host(int sock, char* hostname);
void run_test(FILE* fp);

#define STEP 1
long CALLS_PER_THREAD = 1;
long NUM_THREADS = 50;
long BYTES_TO_FETCH	= 1000000;
long BUFFER_SIZE =1024;
int port = 443;
int verbose = 0;
int ssl = 0;
int report = 1;
int reportAll = 0;
int levels = 0;
static char request[] = "GET /%ld.gar HTTP/1.1\r\nHost: %s\r\n\r\n";
pthread_barrier_t begin_barrier;
pthread_mutex_t	finished_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t finished_sem;
int threads_finished = 0;
char host[] = "www.phoenixteam.net";

int main(int argc, char* argv[]) {
	char* csv_file_name = NULL;
	extern char *optarg;
	extern int optind;
	int c, err = 0, len; 
	static char usage[] = "usage: %s [-b <bufsize> -c <calls per thread> -d <bytes to download>  -f <filename> -h -t <number of threads>]\n";

	static struct option long_options[] =
        {
			{"bufsize",  required_argument, NULL, 'b'},
			{"call",  required_argument, NULL, 'c'},
			{"download",  required_argument, NULL, 'd'},
			{"filename",required_argument,NULL,'f'},
			{"file",required_argument,NULL,'f'},
			{"help",  no_argument, NULL, 'h'},
			{"threads",  required_argument, NULL, 't'},
			{"thread",  required_argument, NULL, 't'}

		};
	int option_index = 0;
	while ((c = getopt_long(argc, argv, "a:b:c:d:f:ht:p:vsr:",long_options,&option_index)) != -1){
		switch (c) {
		case 'a':
			reportAll = 1;
			levels = strtol(optarg,NULL,10);
			break;
		case 'b':
			BUFFER_SIZE = strtol(optarg,NULL,10);
			break;
		case 'c':
			CALLS_PER_THREAD = strtol(optarg,NULL,10);
			break;
		case 'd':
			BYTES_TO_FETCH = strtol(optarg,NULL,10);
			break;	
		case 'f':
			len = strlen(optarg)+1;
			csv_file_name = malloc(sizeof(char)*len);
			memcpy(csv_file_name,optarg,len);
			break;
		case 'h':
			fprintf(stderr, usage, argv[0]);
			return 1;
		case 'r':
			report = strtol(optarg,NULL,0);
			break;
		case 's':
			ssl = 1;
			break;
		case 't':
			NUM_THREADS = strtol(optarg,NULL,10);
			break;
		case 'p':
			port = (int) strtol(optarg,NULL,10);
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			err = 1;
			break;
		}
	}
	if(err){
		fprintf(stderr, usage, argv[0]);
		return 0;
	}
	if(csv_file_name == NULL){
		csv_file_name = malloc(sizeof(char) *10);
		memcpy(csv_file_name,"stats.csv",10);
	}

	FILE *fp;
	struct stat buffer;

	int header = stat(csv_file_name,&buffer);
	fp = fopen(csv_file_name, "a");
	if(header == -1) fprintf(fp, "ssl,numThreads,callsPerThread,bufferSize,amountDownloaded,timeElapsed,KbytesPerSec\n");
	signal(SIGPIPE, SIG_IGN); /* Non-portable but I don't care right now */
	
	if(reportAll){
		for(int x = 0; x < levels; x++){
			if(x == 0){
				NUM_THREADS = 1;
			}else{
				NUM_THREADS = x *STEP;
			}
			for(int r = 0;  r < report; r++){
				run_test(fp);
				printf("finished: %ld Threads test\n",NUM_THREADS);
				fflush(stdout);
				usleep(50000);
			}
		}
	}else{
		for(int r = 0;  r < report; r++){
			run_test(fp);
			usleep(50000);
		}
	}
	fclose(fp);
}
void run_test(FILE* fp){
	int i;
	pthread_t t[NUM_THREADS];
	struct timeval tv_before;
	struct timeval tv_after;
	struct timeval tv_elapsed;
	param_t t_params[NUM_THREADS];
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		//.sin_addr.s_addr = inet_addr("127.0.0.1"),
		.sin_addr.s_addr = inet_addr("45.56.41.23"),
		.sin_port = htons(port)
	};
	pthread_barrier_init(&begin_barrier, NULL, NUM_THREADS + 1);
	sem_init(&finished_sem, 0, 0);
	threads_finished = 0;
	for (int i = 0; i < NUM_THREADS ; i++) {
		t_params[i].id = i;
		if(ssl){
			t_params[i].sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
			if (t_params[i].sock == -1) {
				perror("failed to create a socket");
				exit(EXIT_FAILURE);
			}
			if (connect(t_params[i].sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
				perror("connect");
				exit(EXIT_FAILURE);
			}
			t_params[i].ssl = openssl_connect_to_host(t_params[i].sock,host);
		}else{
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
		}
		pthread_create(&t[i], NULL, thread_start, (void*)&t_params[i]);
	}
	usleep(5000000);
	pthread_barrier_wait(&begin_barrier);
	if(verbose) printf("Threads ready! Start timer!\n");
	gettimeofday(&tv_before, NULL);
	sem_wait(&finished_sem);
	gettimeofday(&tv_after, NULL);
	for(i = 0; i < NUM_THREADS; i++) {
		pthread_join(t[i],NULL);
	}
	if (timeval_subtract(&tv_elapsed, &tv_after, &tv_before) == 1) {
		fprintf(stderr, "Oh no! Difference between after and before was negative!\n");
	}
	double bytes_per_second = ((NUM_THREADS*CALLS_PER_THREAD*BYTES_TO_FETCH)/1000)/((double)tv_elapsed.tv_sec+((double)tv_elapsed.tv_usec/1000000));
	fprintf(fp, "%d,%ld,%ld,%ld,%ld,%ld.%06ld,%.6lf\n", ssl,NUM_THREADS, CALLS_PER_THREAD,BUFFER_SIZE,BYTES_TO_FETCH, tv_elapsed.tv_sec, tv_elapsed.tv_usec,bytes_per_second);
	fflush(fp);
}

void* thread_start(void* arg) {
	int i;
	int sock_fd;
	int thread_id;
	int bytes_read;
	int total_bytes_read;
	char response[BUFFER_SIZE];
	SSL* tls;
	char req[1024];
	//printf(request,BYTES_TO_FETCH,host);
	sprintf(req,request,BYTES_TO_FETCH,host);
	param_t* params = (param_t*)arg;
	thread_id = params->id;
	sock_fd = params->sock;
	tls = params->ssl;

	pthread_barrier_wait(&begin_barrier);

	for(i = 0; i < CALLS_PER_THREAD; i++) {
		total_bytes_read = 0;
		if(ssl){
			SSL_connect(tls);
			if(SSL_write(tls,req,strlen(req)) <= 0){
				printf("SSL Send Error");
				pthread_mutex_lock(&finished_lock);
				NUM_THREADS--;
				if (threads_finished == NUM_THREADS) {
					sem_post(&finished_sem);
				}
				pthread_mutex_unlock(&finished_lock);
				if(ssl) SSL_shutdown(tls);
				close(sock_fd);
				return NULL;
			}
		}else{
			if(send(sock_fd, req,strlen(req),0) == -1){
				perror("thread send:");
				pthread_mutex_lock(&finished_lock);
				NUM_THREADS--;
				if (threads_finished == NUM_THREADS) {
					sem_post(&finished_sem);
				}
				pthread_mutex_unlock(&finished_lock);
				close(sock_fd);
				return NULL;
			}
		}
		while(total_bytes_read < BYTES_TO_FETCH) {
			if(ssl){
				bytes_read = SSL_read(tls,response,BUFFER_SIZE);
			}else{
				bytes_read = recv(sock_fd, response, BUFFER_SIZE ,0);
			}
			if (bytes_read == -1) {
				perror("recv");
				pthread_mutex_lock(&finished_lock);
				NUM_THREADS--;
				if (threads_finished == NUM_THREADS) {
					sem_post(&finished_sem);
				}
				pthread_mutex_unlock(&finished_lock);
				close(sock_fd);
				return NULL;
			}
			else if (bytes_read == 0) {
				if(verbose) printf("Thread ID %d was disconnected\n", thread_id);
			}
			else {
				total_bytes_read += bytes_read;
			}
		}
	}
	if(ssl) SSL_shutdown(tls);
	close(sock_fd);
	if(verbose) printf("Thread %d finished %d iterations\n", thread_id, i);
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
static char root_store_filename_redhat[] = "/etc/pki/tls/certs/ca-bundle.crt";

SSL* openssl_connect_to_host(int sock, char* hostname) {
	SSL_CTX* tls_ctx;
	SSL* tls;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	tls_ctx = SSL_CTX_new(SSLv23_client_method());
	if (tls_ctx == NULL) {
		fprintf(stderr, "Could not create SSL_CTX\n");
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
	
	
	if (SSL_CTX_load_verify_locations(tls_ctx, root_store_filename_redhat, NULL) != 1) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed\n");
		exit(EXIT_FAILURE);
	}

	tls = SSL_new(tls_ctx);
	SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		fprintf(stderr, "SSL_new from tls_ctx failed\n");
		exit(EXIT_FAILURE);
	}

	/* set server name indication for client hello */
	SSL_set_tlsext_host_name(tls, hostname);

	/* Associate socket with TLS context */
	SSL_set_fd(tls, sock);

	/*if (SSL_connect(tls) != 1) {
		fprintf(stderr, "Failed in SSL_connect\n");
		exit(EXIT_FAILURE);
	}*/
	//this code is not being used since we are not validating certs
	/*cert = SSL_get_peer_certificate(tls);
	if (cert == NULL) {
		fprintf(stderr, "Failed to get peer certificate\n");
		exit(EXIT_FAILURE);
	}*/

	/*if (validate_hostname(hostname, cert) != MatchFound) {
		fprintf(stderr, "Failed to validate hostname in certificate\n");
		exit(EXIT_FAILURE);
	}*/

	return tls;
}
