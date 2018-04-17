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

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/bio.h>

#include "log.h"
#include "issue_cert.h"

#define CERT_START "-----BEGIN CERTIFICATE-----"
#define FAIL_MSG "SIGNING REQUEST FAILED"
#define CERT_DAYS 365


typedef struct csr_ctx {
	struct event_base* ev_base;
	X509* ca_cert;
	EVP_PKEY* ca_key;
	int days;
	int serial;
} csr_ctx_t;


static csr_ctx_t* create_csr_ctx(struct event_base* ev_base);
void free_csr_ctx(csr_ctx_t* ctx);
static void csr_read_cb(struct bufferevent *bev, void *ctx);
static void csr_accept_error_cb(struct evconnlistener *listener, void *arg);
static void csr_event_cb(struct bufferevent *bev, short events, void *ctx);
static void csr_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);

int csr_server_create(int port) {
	struct event_base* ev_base = event_base_new();
	struct evconnlistener* listener;
	evutil_socket_t server_sock;
	struct event* sev_pipe;
	struct event* sev_int;
	struct sockaddr_in sin;
	csr_ctx_t* ctx;


	log_printf(LOG_INFO, "Ran CSR server! port %d\n",port);

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

	ctx = create_csr_ctx(ev_base);

	listener = evconnlistener_new_bind(ev_base, csr_accept_cb, ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));

	if (!listener) {
		perror("Couldn't create csr listener");
		return 1;
	}

	evconnlistener_set_error_cb(listener, csr_accept_error_cb);

	event_base_dispatch(ev_base);

	log_printf(LOG_INFO, "CSR Daemon event loop terminated\n");

	free_csr_ctx(ctx);
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */

	return 0;
}

csr_ctx_t* create_csr_ctx(struct event_base* ev_base) {

	csr_ctx_t* ctx;

	ctx = (csr_ctx_t*)malloc(sizeof(csr_ctx_t));
	ctx->ev_base = ev_base;
	ctx->days = CERT_DAYS;
	// Should this be stored and read from a file?
	ctx->serial = 0;

	ctx->ca_cert = get_cert_from_file("test_files/certificate_ca.pem");
	if (ctx->ca_cert == NULL) {
		free(ctx);
		log_printf(LOG_ERROR,"Error loading CA cert\n");
		return NULL;
	}
	ctx->ca_key = get_private_key_from_file("test_files/key_ca.pem");
	if (ctx->ca_key == NULL) {
		free(ctx->ca_cert);
		free(ctx);
		log_printf(LOG_ERROR,"Error loading CA key\n");
		return NULL;
	}
	return ctx;
}

void free_csr_ctx(csr_ctx_t* ctx) {
	// What do you do with the base?
	X509_free(ctx->ca_cert);
	EVP_PKEY_free(ctx->ca_key);
	ENGINE_cleanup();
	free(ctx);
}

// This is not written correctly and needs to not have to read all at once.
void csr_read_cb(struct bufferevent *bev, void *ctx) {

	int cert_len;
	char* csr;
	// char* signed_cert;
	X509* new_cert;
	X509_REQ* cert_req;
	unsigned char *encoded_cert;
	csr_ctx_t* csr_ctx = (csr_ctx_t*)ctx;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t recv_len = evbuffer_get_length(input);
	size_t message_len;


	csr = malloc(recv_len);
	bufferevent_read(bev, csr, recv_len);
	cert_req = get_csr_from_buf(csr);

	new_cert = issue_certificate(cert_req, csr_ctx->ca_cert, csr_ctx->ca_key,
		csr_ctx->serial, csr_ctx->days);

	csr_ctx->serial++;

	if (new_cert == NULL) {
		log_printf(LOG_ERROR,"Certificate issuance failed\n");
		bufferevent_write(bev, FAIL_MSG, sizeof(FAIL_MSG));
		return;
	}

	encoded_cert = net_encode_cert(new_cert,&cert_len);
	if (encoded_cert == NULL) {
		log_printf(LOG_ERROR,"Certificate unable to be serialized\n");
		bufferevent_write(bev, FAIL_MSG, sizeof(FAIL_MSG));
		free(csr);
		return;
	}

	bufferevent_write(bev, encoded_cert, cert_len);

	free(csr);
	free(encoded_cert);
	X509_REQ_free(cert_req);
	X509_free(new_cert);

	
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
	// csr_ctx_t* ctx = (csr_ctx_t*)arg;

	log_printf(LOG_INFO, "Received CSR connection!\n");

	// if (evutil_make_socket_nonblocking(fd) == -1) {
	// 	log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
	// 		 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	// 	EVUTIL_CLOSESOCKET(fd);
	// 	return;
	// }

	/* We got a new connection! Set up a bufferevent for it. */
	bufferevent_setcb(bev, csr_read_cb, NULL, csr_event_cb, arg);
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
