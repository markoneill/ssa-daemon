/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017-2018, Mark O'Neill <mark@markoneill.name>
 * All rights reserved.
 * https://owntrust.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <wait.h>
#include "daemon.h"
#include "log.h"
#include "config.h"
#include "auth_daemon.h"
#include "csr_daemon.h"
#include "nsd.h"
#include "self_sign.h"

void sig_handler(int signum);
void* create_nsd_daemon(void* arg);
void* create_csr_daemon(void* arg);
void* create_auth_daemon(void* arg);
	
pid_t* workers;
int worker_count;
int is_parent;

typedef struct daemon_param {
	int port;
	EVP_PKEY* pub_key;
} daemon_param_t;

int main(int argc, char* argv[]) {
	long cpus_on;
	long cpus_conf;
	int i;
	pid_t pid;
	struct sigaction sigact;
	int status;
	int ret;
	int starting_port = 8443;
	pthread_t csr_daemon;
	daemon_param_t csr_params = {
		.port = 8040
	};
	#ifdef CLIENT_AUTH
	daemon_param_t auth_params = {
		.port = 6666
	};
	pthread_t auth_daemon;
	#endif

	/* Init logger */
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}

	if (geteuid() != 0) {
		log_printf(LOG_ERROR, "Please run as root\n");
		exit(EXIT_FAILURE);
	}

	cpus_on = sysconf(_SC_NPROCESSORS_ONLN);
	cpus_conf = sysconf(_SC_NPROCESSORS_CONF);
	log_printf(LOG_INFO, "Detected %ld/%ld active CPUs\n", cpus_on, cpus_conf);


	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	sigaction(SIGINT, &sigact, NULL);

	parse_config("ssa.cfg");
	
	worker_count = 1;

	workers = malloc(sizeof(pid_t) * worker_count);
	if (workers == NULL) {
		log_printf(LOG_ERROR, "Failed to malloc space for workers\n");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < worker_count; i++) {
		pid = fork();
		if (pid == -1) {
			log_printf(LOG_ERROR, "%s", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (pid == 0) {
			server_create(starting_port + i);
			free(workers);
			return 0;
		}
		else {
			workers[i] = pid;
			is_parent = 1;
		}
	}

	pthread_create(&csr_daemon, NULL, create_csr_daemon, (void*)&csr_params);
	#ifdef CLIENT_AUTH
	pthread_create(&auth_daemon, NULL, create_auth_daemon, (void*)&auth_params);
	#endif

	while ((ret = wait(&status)) > 0) {
		if (ret == -1) {
			log_printf(LOG_ERROR, "Failed in waitpid %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (WIFEXITED(status)) {
			log_printf(LOG_INFO, "worker exited, status %d\n", WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status)) {
				log_printf(LOG_INFO, "worker killed by signal %d\n", WTERMSIG(status));
		}
		else if (WIFSTOPPED(status)) {
			log_printf(LOG_INFO, "worker stopped by signal %d\n", WSTOPSIG(status));
		}
		else if (WIFCONTINUED(status)) {
			log_printf(LOG_INFO, "worker continued\n");
		}
	}

	/*pthread_join(csr_daemon, NULL);
	pthread_join(auth_daemon, NULL);*/

	log_close();
	free_config();
	free(workers);
	return 0;
}

void sig_handler(int signum) {
	int i;
	if (signum == SIGINT) {
		if (is_parent == 1) {
			for (i = 0; i < worker_count; i++) {
				kill(workers[i], SIGINT);
			}
		}
		else {
			free(workers);
			_exit(0);
		}
	}
	return;
}

void* create_nsd_daemon(void* arg) {
	daemon_param_t* params = (daemon_param_t*)arg;
	int port = params->port;
	EVP_PKEY *pub_key = params->pub_key;	
	register_auth_service(port, pub_key);
	return NULL;
}

void* create_csr_daemon(void* arg) {
	daemon_param_t* params = (daemon_param_t*)arg;
	int csr_daemon_port = params->port;
	csr_server_create(csr_daemon_port);
	return NULL;
}

void* create_auth_daemon(void* arg) {
	daemon_param_t* params = (daemon_param_t*)arg;
	int port = params->port;
	pthread_t nsd_daemon;
	daemon_param_t nsd_params;
	int status, pid;
	BIO *pembio;
	X509 *cert;
	EVP_PKEY *pkey;	

	if (generate_rsa_key(&pkey, 2048) == 0) {
		fprintf(stderr, "Failed to generate RSA key\n");
		return NULL;
	}

	cert = generate_self_signed_certificate(pkey, 0, 365);
	if (cert == NULL) {
		fprintf(stderr, "Failed to generate self signed certificate\n");
		return NULL;
	}

	nsd_params.port = port;
	if (!(nsd_params.pub_key = X509_get_pubkey(cert))) {
		fprintf(stderr, "Failed to extract the public key from the certificate\n");
		return NULL;
	}
	
	pembio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(pembio, nsd_params.pub_key); 	

	char* keyString;
	char* copy;
	int len = BIO_get_mem_data(pembio, &keyString);
	int pipefd[2], i, j;
	pipe(pipefd);
	char* argv[6];
	argv[0] = "qrencode";
	argv[1] = "-o";
	argv[2] = QRIMG_PATH;
	argv[3] = "-s";
	argv[4] = "6";
	argv[5] = NULL;
	
	copy = strdup(keyString);
	for (i = j = 0; copy[j] != 0; j++) {
		if (copy[j] != '\n')
			copy[i++] = copy[j];
	}
	copy[i] = 0;

	if((pid = fork())) {
		if (pid == -1) {
			fprintf(stderr, "could not create QRCode, Call to fork failed\n");
			return NULL;
		}
		close(pipefd[0]);          /* Close unused read end */
		write(pipefd[1], copy, len);
		close(pipefd[1]);          /* Reader will see EOF */
		waitpid(pid,&status,0);
	} else {

		close(pipefd[1]);          /* Close unused write end */
		close(STDIN_FILENO);	   /* repalce stdin with reed end */
		status = dup2(pipefd[0], STDIN_FILENO);
		if (status != STDIN_FILENO)
		{
			perror("dup2 error\n");
			return NULL;
		}

		execv("/usr/bin/qrencode", argv);
		printf("something went wrong in create_auth_daemon child\n");
		exit(-1);
	}
	
	free(copy);
	BIO_free(pembio);	
	pthread_create(&nsd_daemon, NULL, create_nsd_daemon, (void*)&nsd_params);

	auth_server_create(port, cert, pkey);
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return NULL;
}
