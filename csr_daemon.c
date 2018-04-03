#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <assert.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "log.h"

// #include <openssl/bio.h>
// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/rand.h>

#define CERT_START "-----BEGIN CERTIFICATE-----"

static void run_singing(char* buff);
static void csr_read_cb(struct bufferevent *bev, void *ctx);
static void csr_accept_error_cb(struct evconnlistener *listener, void *arg);
static void csr_event_cb(struct bufferevent *bev, short events, void *ctx);
static void csr_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);

static int sign_cert(char* csr, char** signed_cert);
static int write_cert(char* csr_file, char* csr);
static int read_cert(char* cert_file, char** cert);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);

typedef struct csr_ctx {
	struct event_base* ev_base;
	char* csr;
	int csr_len;
} csr_ctx_t;

int csr_server_create(int port) {
	log_printf(LOG_INFO, "Ran CSR server! port %d\n",port);

	struct event_base* ev_base = event_base_new();
	struct evconnlistener* listener;
	evutil_socket_t server_sock;
	struct event* sev_pipe;
	struct event* sev_int;
	struct sockaddr_in sin;

		/* Signal handler registration */
	sev_pipe = evsignal_new(ev_base, SIGPIPE, csr_signal_cb, NULL);
	if (sev_pipe == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGPIPE handler event\n");
		return 1;
	}
	sev_int = evsignal_new(ev_base, SIGINT, csr_signal_cb, ev_base);
	if (sev_int == NULL) {
		log_printf(LOG_ERROR, "Couldn't create SIGINT handler event\n");
		return 1;
	}
	evsignal_add(sev_pipe, NULL);
	evsignal_add(sev_int, NULL);


	// server_sock = create_server_socket(port, PF_INET, SOCK_STREAM);
	// listener = evconnlistener_new(ev_base, csr_accept_cb, NULL, 
	// 	LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, 0, server_sock);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0);
	sin.sin_port = htons(port);

	listener = evconnlistener_new_bind(ev_base, csr_accept_cb, NULL, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));

	if (!listener) {
		perror("Couldn't create csr listener");
		return 1;
	}

	evconnlistener_set_error_cb(listener, csr_accept_error_cb);

	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "CSR Daemon event loop terminated\n");

	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */

	return 0;
}


void run_singing(char* buff) {
	return;
}

// This is not written correctly and needs to not have to read all at once.
void csr_read_cb(struct bufferevent *bev, void *ctx) {

	int cert_len;
	char* csr;
	char* signed_cert;
	char sorry[] = "Unable to sign cert";

	struct evbuffer *input = bufferevent_get_input(bev);
	// struct evbuffer *output = bufferevent_get_output(bev);
	size_t recv_len = evbuffer_get_length(input);
	size_t message_len;

	csr = malloc(recv_len);

	bufferevent_read(bev, csr, recv_len);

	cert_len = sign_cert(csr, &signed_cert);

	if(cert_len == -1) {
		log_printf(LOG_ERROR, "Unable to sign csr reqeust\n");
		bufferevent_write(bev, sorry, sizeof(sorry));
		return;
	}

	bufferevent_write(bev, signed_cert, cert_len);
	// evbuffer_add_buffer(output, input);

	free(signed_cert);
	free(csr);
}


void csr_accept_error_cb(struct evconnlistener *listener, void *arg) {
	struct event_base *base = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();
	log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n", 
			err, evutil_socket_error_to_string(err));
	event_base_loopexit(base, NULL);
	return;
}

void csr_event_cb(struct bufferevent *bev, short events, void *ctx) {
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		log_printf(LOG_INFO,"Free connection\n");
		bufferevent_free(bev);
	}
}

void csr_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {

	struct event_base *ev_base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(ev_base, fd, BEV_OPT_CLOSE_ON_FREE);

	log_printf(LOG_INFO, "Received CSR connection!\n");

	// if (evutil_make_socket_nonblocking(fd) == -1) {
	// 	log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
	// 		 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	// 	EVUTIL_CLOSESOCKET(fd);
	// 	return;
	// }

	/* We got a new connection! Set up a bufferevent for it. */
	bufferevent_setcb(bev, csr_read_cb, NULL, csr_event_cb, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	return;
}

void csr_signal_cb(evutil_socket_t fd, short event, void* arg) {
	int signum = fd; /* why is this fd? */
	switch (signum) {
		case SIGPIPE:
			log_printf(LOG_DEBUG, "Caught SIGPIPE and ignored it\n");
			break;
		case SIGINT:
			log_printf(LOG_DEBUG, "Caught SIGINT\n");
			event_base_loopbreak(arg);
			break;
		default:
			break;
	}
	return;
}

int read_cert(char* cert_file, char** cert) {
	long file_size;
	size_t cert_size;
	FILE *fp = fopen(cert_file, "r");
	char * hold;

	if (fp != NULL) {

		if (fseek(fp, 0L, SEEK_END) == 0) {

			file_size = ftell(fp);
			if (file_size == -1) {
				*cert = NULL;
				return 0;
			}

			*cert = malloc(sizeof(char) * (file_size + 50));

			if (fseek(fp, 0L, SEEK_SET) != 0) {
				free(*cert);
				*cert = NULL;
				return 0;
			}

			cert_size = fread(*cert, sizeof(char), file_size, fp);
			if (ferror( fp ) != 0) {
				
				free(*cert);
				*cert = NULL;
				return 0;
			} 
			else {
				hold = *cert;
				hold[cert_size++] = '\0';
			}
		}
		fclose(fp);
	}

	return 1;
}

int write_cert(char* csr_file, char* csr) {
	FILE* fp = fopen(csr_file,"wb");

	if (fp){
		fwrite(csr, sizeof(char), strlen(csr), fp);
	}
	else{
		return 0;
	}

	fclose(fp);
	return 1;
}

int sign_cert(char* csr, char** signed_cert) {
	pid_t childpid;
	int status;
	char cert_file[] = "personal.crt";
	char tmp_csr[] = "tmp.csr";
	char* full_cert;
	char* cert_no_summary;
	size_t cert_len;

	// write the cert we care about to disk
	if(!write_cert(tmp_csr,csr)) {
		log_printf(LOG_ERROR,"Unable to write CSR file:%s\n",tmp_csr);
		*signed_cert = NULL;
		return -1;
	}


	int dev_null_fd = open("/dev/null", O_RDWR);
  	if (dev_null_fd < 0) perror("Unable to open /dev/null");

	if((childpid = fork()) == -1) {
		perror("fork csr singing");
		*signed_cert = NULL;
		return -1;
	}

	if(childpid == 0) {
		dup2(dev_null_fd, 1);
		dup2(dev_null_fd, 2);

		execlp("openssl","openssl","ca","-config","openssl-ca.cnf","-batch","-policy","signing_policy",
			"-extensions","signing_req","-out",cert_file,"-infiles",tmp_csr,NULL);
 		exit(-1);
	}
	
	if (waitpid(childpid, &status, 0) > 0) {

		if (WIFEXITED(status) && !WEXITSTATUS(status)) {
			// Finished successfully
			//printf("Success\n");
		}

		else if (WIFEXITED(status) && WEXITSTATUS(status)) {
			if (WEXITSTATUS(status) == 127) {
				log_printf(LOG_ERROR,"Unable to start openssl ca to sign cert\n");
				*signed_cert = NULL;
				return -1;
			}
			else {
				log_printf(LOG_INFO,"Openssl csr signing terminated normally, but returned a non-zero status\n");
			}
		}
		else {
			log_printf(LOG_INFO,"Openssl csr signing didn't terminate normally\n");
		}
	} 
	else {
		log_printf(LOG_ERROR,"Unable to write tmp CSR file\n");
		*signed_cert = NULL;
		return -1;
	}

	if(!read_cert(cert_file,&full_cert)) {
		log_printf(LOG_ERROR,"Unable to read tmp CSR file:%s\n",cert_file);
		*signed_cert = NULL;
		return -1;
	}

	if (unlink(cert_file) && unlink(tmp_csr))
	{
		printf("Unable to remove singed cert %s or csr request %s %s\n",cert_file,tmp_csr);
		return 1;
	}

	// Better way to do this?
	cert_no_summary = strstr(full_cert,CERT_START);
	cert_len = strlen(cert_no_summary);
	*signed_cert = malloc(cert_len);
	strncpy(*signed_cert,cert_no_summary,cert_len);
	free(full_cert);

	return cert_len;
}