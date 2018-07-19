#include <stdio.h>
#include <signal.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/bio.h>


#include "log.h"
#include "issue_cert.h"

#define FAIL_MSG "SIGNING REQUEST FAILED"
#define CERT_DAYS 365
#define CERT_PATH "test_files/certificate_a.pem"
#define KEY_PATH "test_files/key_a.pem"


typedef struct csr_ctx {
	struct event_base* ev_base;
	X509* ca_cert;
	EVP_PKEY* ca_key;
	int days;
	int serial;
	SSL_CTX* tls_ctx;
} csr_ctx_t;

typedef struct con_ctx {
	csr_ctx_t* ctx;
	char* cert;
	int length;
	int max_length;
} con_ctx_t;

typedef struct totp_ctx {
	int phone_num_len;
	char* phone_num;
} totp_ctx_t;

typedef struct validate_totp_ctx {
	long access_code;
	char* totp;
	con_ctx_t* con_ctx;
} validate_totp_ctx_t;


static csr_ctx_t* create_csr_ctx(struct event_base* ev_base);
void free_csr_ctx(csr_ctx_t* ctx);
static SSL_CTX * ssl_ctx_init(void);
static void csr_read_cb(struct bufferevent *bev, void *ctx);
static void csr_accept_error_cb(struct evconnlistener *listener, void *arg);
static void csr_event_cb(struct bufferevent *bev, short events, void *ctx);
static void csr_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *ctx);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);
static void csr_signal_cb(evutil_socket_t fd, short event, void* arg);
static void new_read_cb(struct bufferevent *bev, void *ctx);
static void new_event_cb(struct bufferevent *bev, short events, void *ctx);
static void totp_read_cb(struct bufferevent *bev, void *ctx);
static void totp_event_cb(struct bufferevent *bev, short events, void *ctx);


int csr_server_create(int port) {
	struct event_base* ev_base = event_base_new();
	struct evconnlistener* listener;
	evutil_socket_t server_sock;
	struct event* sev_pipe;
	struct event* sev_int;
	struct sockaddr_in sin;
	csr_ctx_t* ctx;


	log_printf(LOG_INFO, "Started CSR server. port %d\n",port);

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
	evconnlistener_free(listener); /* This also closes the socket due to our listener creation flags */
	event_free(sev_pipe);
	event_free(sev_int);
	free_csr_ctx(ctx);
	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
		libevent_global_shutdown();
	#endif
	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_cleanup();
	#else
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	SSL_COMP_free_compression_methods();
	#endif
	

	return 0;
}

totp_ctx_t* create_totp_ctx(struct event_base* ev_base) {

	totp_ctx_t* ctx;

	ctx = (totp_ctx_t*)malloc(sizeof(totp_ctx_t));
	ctx->phone_num_len = 0;
	ctx->phone_num = NULL;

	return ctx;
}

validate_totp_ctx_t* create_validate_totp_ctx(struct event_base* ev_base) {

	validate_totp_ctx_t* ctx;

	ctx = (validate_totp_ctx_t*)malloc(sizeof(validate_totp_ctx_t));
	ctx->access_code = 0;
	ctx->totp = NULL;
	ctx->con_ctx = NULL;

	return ctx;
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
	ctx->tls_ctx = ssl_ctx_init();
	if (ctx->tls_ctx == NULL)
	{
		free(ctx->ca_cert);
		free(ctx);
		log_printf(LOG_ERROR,"Error creating SSL CTX\n");
		return NULL;
	}

	return ctx;
}

void free_csr_ctx(csr_ctx_t* ctx) {
	// What do you do with the base?
	event_base_free(ctx->ev_base);
	X509_free(ctx->ca_cert);
	EVP_PKEY_free(ctx->ca_key);
	ENGINE_cleanup();
	SSL_CTX_free(ctx->tls_ctx);
	free(ctx);
}

static SSL_CTX * ssl_ctx_init(void) {
	SSL_CTX  *tls_ctx;

	SSL_load_error_strings();
	SSL_library_init();

	tls_ctx = SSL_CTX_new(SSLv23_server_method());

	if (! SSL_CTX_use_certificate_chain_file(tls_ctx, CERT_PATH) ||
	! SSL_CTX_use_PrivateKey_file(tls_ctx, KEY_PATH, SSL_FILETYPE_PEM)) {
		log_printf(LOG_ERROR,"Error reading csr certificate and key files\n");
		return NULL;
	}
	SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2);

	return tls_ctx;
}


char* otp_request(char *request, struct bufferenvent *bev, void *con) {
	long length = request[1];
	char* phone_number;
	// read phone number from request
	char* totp = generate_totp();
	const char* error;
	// add totp to cache
	// hashmap_create
	// hashmap_add(totp);
	twilio_send_message(phone_number, totp, error);
	// send back the access code
	bufferevent_write(bev, "santi", 8);
	return totp;
}

/**
 *  Write the cert from the evbuffer into the given connection_context->cert
 */
int copy_cert(struct bufferevent *bev, con_ctx_t *con) {
	return 0;
}

// This is not written correctly and needs to not have to read all at once.
void csr_read_cb(struct bufferevent *bev, void *con) {

	int cert_len = 0;
	X509* new_cert;
	X509_REQ* cert_req;
	char *encoded_cert;
	con_ctx_t* con_ctx = (con_ctx_t*)con;
	csr_ctx_t* csr_ctx = con_ctx->ctx;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t recv_len = evbuffer_get_length(input);

	if (con_ctx->max_length < (con_ctx->length + recv_len)) {
		if (con_ctx->max_length < recv_len*2) {
			con_ctx->max_length = recv_len*2;
		}
		else {
			con_ctx->max_length = con_ctx->max_length*2;
		}
		
		con_ctx->cert = realloc(con_ctx->cert,con_ctx->max_length);
	}
	bufferevent_read(bev, con_ctx->cert+con_ctx->length, recv_len);
	con_ctx->length += recv_len;
	// Check if last byte is null byte and we are done receiving
	if (con_ctx->cert[con_ctx->length-1] != '\x00' ) {
		return;
	}

	cert_req = get_csr_from_buf(con_ctx->cert);

	new_cert = issue_certificate(cert_req, csr_ctx->ca_cert, csr_ctx->ca_key,
		csr_ctx->serial, csr_ctx->days);

	csr_ctx->serial++;

	if (new_cert == NULL) {
		log_printf(LOG_ERROR,"Certificate issuance failed\n");
		bufferevent_write(bev, FAIL_MSG, sizeof(FAIL_MSG));
		return;
	}

	encoded_cert = X509_to_PEM(new_cert,&cert_len);

	if (encoded_cert == NULL) {
		log_printf(LOG_ERROR,"Certificate unable to be serialized\n");
		bufferevent_write(bev, FAIL_MSG, sizeof(FAIL_MSG));
		free(con_ctx->cert);
		con_ctx->cert = NULL;
		//free(csr);
		return;
	}

	bufferevent_write(bev, encoded_cert, cert_len);

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

void csr_event_cb(struct bufferevent *bev, short events, void *con) {
	con_ctx_t* con_ctx = (con_ctx_t*)con;

	if (events & BEV_EVENT_ERROR)
		// Do I need to free here?
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		// Free ctx pntr
		if (con_ctx != NULL) {
			if (con_ctx->cert != NULL) {
				free(con_ctx->cert);
			}
			free(con_ctx);
		}
		log_printf(LOG_INFO,"Free connection\n");
		bufferevent_free(bev);
	}
}

void csr_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {

	csr_ctx_t* ctx = (csr_ctx_t*)arg;
	SSL* ssl = SSL_new(ctx->tls_ctx);
	con_ctx_t* con = NULL;

	struct event_base *ev_base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_openssl_socket_new(ev_base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	log_printf(LOG_INFO, "Received CSR connection.\n");

	// if (evutil_make_socket_nonblocking(fd) == -1) {
	// 	log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
	// 		 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
	// 	EVUTIL_CLOSESOCKET(fd);
	// 	return;
	// }

	bufferevent_setcb(bev, new_read_cb, NULL, new_event_cb, NULL);
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

void new_event_cb(struct bufferevent *bev, short events, void *ctx) {
	printf("New Event Callback invoked\n");
}

void totp_read_cb(struct bufferevent *bev, void *ctx) {
	printf("TOTP READ CALLBACK INVOKED.");
}

void totp_event_cb(struct bufferevent *bev, short events, void *ctx) {
	printf("TOTP EVENT CALLBACK INVOKED.");
}


void validate_totp_read_cb(struct bufferevent *bev, void *ctx) {
	printf("TOTP VALIDATE READ CALLBACK INVOKED.");
}

void validate_totp_event_cb(struct bufferevent *bev, short events, void *ctx) {
	printf("TOTP VALIDATE EVENT CALLBACK INVOKED.");
}

void new_read_cb(struct bufferevent *bev, void *ctx) {
	printf("New Read Callback invoked\n");
	if (ctx != NULL)
		printf("Context Not defined for new_read_cb\n");

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t recv_len = evbuffer_get_length(input);
	char* first_byte = NULL;
	int request_num = -1;
    void *req_ctx = NULL;

	if (recv_len >= 1) {
		bufferevent_read(bev, first_byte, 1);
		if (isdigit(first_byte)) {
			request_num = atoi(first_byte);
		} else {
			printf("Bad Request. First byte is not a number: %s\n", first_byte);
			// close connection
		}

		switch (request_num) {
			case 0:
				req_ctx = create_totp_ctx(NULL);
				// set callback to otp_request
				bufferevent_setcb(bev, totp_read_cb, NULL, totp_event_cb, req_ctx);
				printf("Updated callback to totp req\n");
				break;
			case 1:
				req_ctx = create_validate_totp_ctx(NULL);
				// set callback to validation
				bufferevent_setcb(bev, validate_totp_read_cb, NULL, validate_totp_event_cb, req_ctx);
				printf("Updated callback to validate totp\n");
				break;
			case 2:
				req_ctx = create_csr_ctx(NULL);
				// set callback to CSR
				bufferevent_setcb(bev, csr_read_cb, NULL, csr_event_cb, req_ctx);
				printf("Updated callback to csr\n");
				break;
			default:
				printf("Bad Request. First Byte is not a number between 0 and 2: %s\n");
				// close connection
		}
		if (ctx != NULL)
			free(ctx);
        if (first_byte != NULL)
            free(first_byte);
	}
}

