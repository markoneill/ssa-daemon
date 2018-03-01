/*
 * TLS Wrapping Daemon - transparent TLS wrapping of plaintext connections
 * Copyright (C) 2017, Mark O'Neill <mark@markoneill.name>
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

#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls_wrapper.h"
#include "log.h"

#define MAX_BUFFER		1024*1024*10
#define IPPROTO_TLS 	(715 % 255)

static SSL* tls_server_setup(SSL_CTX* tls_ctx);
static SSL* tls_client_setup(SSL_CTX* tls_ctx, char* hostname);
static void tls_bev_write_cb(struct bufferevent *bev, void *arg);
static void tls_bev_read_cb(struct bufferevent *bev, void *arg);
static void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg);
static int server_name_cb(SSL* tls, int* ad, void* arg);

static tls_conn_ctx_t* new_tls_conn_ctx();
static void free_tls_conn_ctx(tls_conn_ctx_t* ctx);

tls_conn_ctx_t* tls_client_wrapper_setup(evutil_socket_t ifd, evutil_socket_t efd,
		struct event_base* ev_base, char* hostname, int is_accepting, SSL_CTX* tls_ctx) {
	
	/* ctx will hold all data for interacting with the connection to
	 *  the application server socket and the remote socket (client)
	 *
	 * ctx->cf = local client (application)
	 * ctx->sf = remote server
	 *
	 **/
	tls_conn_ctx_t* ctx = new_tls_conn_ctx();
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate tls_conn_ctx_t: %s\n", strerror(errno));
		return NULL;
	}
	ctx->tls = tls_client_setup(tls_ctx, hostname);
	if (ctx->tls == NULL) {
		log_printf(LOG_ERROR, "Failed to set up TLS (SSL*) context\n");
		free_tls_conn_ctx(ctx);
		return NULL;
	}

	ctx->cf.bev = bufferevent_socket_new(ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	ctx->cf.connected = 1;
	if (ctx->cf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [direct mode]\n");
		/* Need to close socket because it won't be closed on free since bev creation failed */
		EVUTIL_CLOSESOCKET(ifd);
		free_tls_conn_ctx(ctx);
		return NULL;
	}


	if (is_accepting == 1) { /* TLS server role */
		ctx->sf.bev = bufferevent_openssl_socket_new(ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}
	else { /* TLS client role */
		ctx->sf.bev = bufferevent_openssl_socket_new(ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	if (ctx->sf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [direct mode]\n");
		free_tls_conn_ctx(ctx);
		return NULL;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->sf.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */


	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(ctx->sf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->sf.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(ctx->cf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->cf.bev, EV_READ | EV_WRITE);

	/* Connect server facing socket */
	/*if (bufferevent_socket_connect(ctx->sf.bev, (struct sockaddr*)server_addr, server_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect [direct mode]: %s\n", strerror(errno));
		free_tls_conn_ctx(ctx);
		return;
	}*/
	//SSL_connect(ctx->tls);
	return ctx;
}

tls_conn_ctx_t* tls_server_wrapper_setup(evutil_socket_t efd, evutil_socket_t ifd,
	       	struct event_base* ev_base, SSL_CTX* tls_ctx, 
		struct sockaddr* internal_addr, int internal_addrlen) {

	/*  ctx will hold all data for interacting with the connection to
	 *  the application server socket and the remote socket (client)
	 *
	 * ctx->cf = remote client
	 * ctx->sf = local server (application)
	 *
	 *  */
	tls_conn_ctx_t* ctx = new_tls_conn_ctx();
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate server tls_conn_ctx_t: %s\n", strerror(errno));
		return NULL;
	}
	
	ctx->tls = tls_server_setup(tls_ctx);
	ctx->cf.bev = bufferevent_openssl_socket_new(ev_base, efd, ctx->tls,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	ctx->cf.connected = 1;
	if (ctx->cf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(efd);
		free_tls_conn_ctx(ctx);
		return NULL;
	}
	
	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->cf.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	ctx->sf.bev = bufferevent_socket_new(ev_base, ifd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (ctx->sf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up server facing bufferevent [listener mode]\n");
		EVUTIL_CLOSESOCKET(ifd);
		free_tls_conn_ctx(ctx);
		return NULL;
	}
	
	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(ctx->sf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->sf.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(ctx->cf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->cf.bev, EV_READ | EV_WRITE);
	
	/* Connect to local application server */
	if (bufferevent_socket_connect(ctx->sf.bev, internal_addr, internal_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect [listener mode]: %s\n", strerror(errno));
		free_tls_conn_ctx(ctx);
		return;
	}
	return ctx;
}

/* XXX Parameterize later
 * Suggestion: Perhaps look up privkey and cert in a
 * protected ssa store with a hostname as an index?
 *
 * The lame option is to have the programmer decide what cert
 * and key to use. We can support this, but the other option seems cool too.
 *
 * If the certificate doesn't exist, do we try to use Let's Encrypt to
 * dynamically get one?
 */
SSL_CTX* tls_server_ctx_create(void) {
	SSL_CTX* tls_ctx = SSL_CTX_new(SSLv23_method());
	if (tls_ctx == NULL) {
		log_printf(LOG_ERROR, "Failed in SSL_CTX_new() [server]\n");
		return NULL;
	}
	SSL_CTX_set_options(tls_ctx, SSL_OP_ALL);
	/* There's a billion options we can/should set here by admin config XXX
 	 * See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */


	/* XXX We can do all sorts of caching modes and define our own callbacks
	 * if desired */	
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_SERVER);

	/* SNI configuration */
	SSL_CTX_set_tlsext_servername_callback(tls_ctx, server_name_cb);
	//SSL_CTX_set_tlsext_servername_arg(tls_ctx, ctx);

	//SSL_CTX_use_certificate_file(tls_ctx, "test_files/certificate.pem", SSL_FILETYPE_PEM);
	//SSL_CTX_use_certificate_chain_file(tls_ctx, "test_files/certificate.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_certificate_chain_file(tls_ctx, "test_files/certificate.pem");
	SSL_CTX_use_PrivateKey_file(tls_ctx, "test_files/key.pem", SSL_FILETYPE_PEM);

	return tls_ctx;
}

SSL_CTX* tls_client_ctx_create(void) {
	SSL_CTX* tls_ctx = SSL_CTX_new(SSLv23_method());
	if (tls_ctx == NULL) {
		log_printf(LOG_ERROR, "Failed in SSL_CTX_new() [server]\n");
		return NULL;
	}
	SSL_CTX_set_options(tls_ctx, SSL_OP_ALL);

	/* We're going to commit the cardinal sin for a bit. Hook up TrustBase here XXX */
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);

	/* There's a billion options we can/should set here by admin config XXX
 	 * See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */


	/* Should also allow some sort of session resumption here XXX
  	 * See SSL_set_session for details  */


	/* For client auth portion of the SSA utilize 
	 * SSL_CTX_set_default_passwd_cb */

	return tls_ctx;
}

int set_trusted_peer_certificates(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* value, int len) {
	//SSL_CTX_add_client_CA_list(tls_ctx, ...);
	return 1;
}

int set_alpn_protos(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* protos) {
	char* next;
	char* proto;
	int proto_len;
	char alpn_string[256];
	int alpn_len;
	char* alpn_str_ptr;
	proto = protos;
	alpn_str_ptr = alpn_string;
	memset(alpn_string, 0, sizeof(alpn_string));
	while ((next = strchr(proto, ',')) != NULL) {
		*next = '\0';
		proto_len = strlen(proto);
		alpn_str_ptr[0] = proto_len;
		alpn_str_ptr++;
		memcpy(alpn_str_ptr, proto, proto_len);
		alpn_str_ptr += proto_len;
		proto = next + 1; /* +1 to skip delimeter */
	}
	alpn_len = strlen(alpn_string);
	if (SSL_CTX_set_alpn_protos(tls_ctx, alpn_string, alpn_len) == 1) {
		return 0;
	}
	return 1;
}

int set_disbled_cipher(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* cipher) {
	//SSL_CTX_set_cipher_list
	return 1;
}

int set_session_ttl(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* ttl) {
	long timeout;
	timeout = strtol(ttl, NULL, 10);
	if (conn_ctx != NULL) {
		return SSL_SESSION_set_timeout(conn_ctx->tls, timeout);
	}
	SSL_CTX_set_timeout(tls_ctx, timeout);
	return 1;
}

int set_certificate_chain(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* filepath) {
	log_printf(LOG_INFO, "Using cert located at %s\n", filepath);
	if (conn_ctx != NULL) {
		if (SSL_use_certificate_chain_file(conn_ctx->tls, filepath) != 1) {
			/* Get ready for renegotiation */
			return 0;
		}
		return 1;
	}
	if (SSL_CTX_use_certificate_chain_file(tls_ctx, filepath) != 1) {
		return 0;
	}
	return 1;
}

int set_private_key(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* filepath) {
	log_printf(LOG_INFO, "Using key located at %s\n", filepath);
	if (conn_ctx != NULL) {
		if (SSL_use_PrivateKey_file(conn_ctx->tls, filepath, SSL_FILETYPE_PEM) == 1) {
			/* Renegotiate now? */
			return 0;
		}
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(tls_ctx, filepath, SSL_FILETYPE_PEM) != 1) {
		return 0;
	}
	/* Should call these as appropriate in this func */
	//SSL_CTX_check_private_key
	//SSL_check_private_key
	return 1;
}

int set_hostname(SSL_CTX* tls_ctx, tls_conn_ctx_t* conn_ctx, char* hostname) {
	if (conn_ctx == NULL) {
		/* We don't fail here because this will be set when the
		 * connection is actually created by tls_client_setup */
		return 1;
	}
	SSL_set_tlsext_host_name(conn_ctx->tls, hostname);
	return 1;
}


int peer_certificate_cb(tls_daemon_ctx_t* ctx, unsigned long id, SSL* ssl) {
	X509 * cert;
	BIO * bio;
	char* bio_data;
	char* pem_data;
	unsigned int len = 0;

	if (!SSL_is_init_finished(ssl)) {
		log_printf(LOG_ERROR, "Requested certificate before handshake completed\n");
		netlink_notify_kernel(ctx, id, -ENOTCONN);
	}

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		netlink_notify_kernel(ctx, id, -ENOTCONN);
		return 0;
	}
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		X509_free(cert);
		netlink_notify_kernel(ctx, id, -ENOTCONN);
		return 0;
	}
	if (PEM_write_bio_X509(bio, cert) == 0) {
		X509_free(cert);
		BIO_free(bio);
		netlink_notify_kernel(ctx, id, -ENOTCONN);
		return 0;
	}

	len = BIO_get_mem_data(bio, &bio_data);
	pem_data = malloc((len) + 1); /* +1 for null terminator */
	if (pem_data == NULL) {
		X509_free(cert);
		BIO_free(bio);
		netlink_notify_kernel(ctx, id, -ENOTCONN);
		return 0;
	}

	memcpy(pem_data, bio_data, len);
	pem_data[len] = '\0';
	X509_free(cert);
	BIO_free(bio);

	if (pem_data == NULL) {
		log_printf(LOG_DEBUG, "pem_data Call\n");
		netlink_notify_kernel(ctx, id, -ENOTCONN);
		return 0;
	}
	netlink_send_and_notify_kernel(ctx, id, pem_data, len);
	free(pem_data);
	return 1;
}

void certificate_handshake_cb(SSL *s, int where, int ret)
{
	unsigned long * id;
	tls_daemon_ctx_t* ctx;
	int id_len = sizeof(id);
	int fd = SSL_get_wfd(s);

	if(where == SSL_CB_HANDSHAKE_DONE)
	{

		/* Get the id and daemon_ctx from the SSL object */
		id = SSL_get_ex_data(s, OPENSSL_EX_DATA_ID);
		ctx = SSL_get_ex_data(s, OPENSSL_EX_DATA_CTX);

		peer_certificate_cb(ctx,*id,s);

		/* free the id becuase we only use it for this function. */
		free(id);
		SSL_set_ex_data(s, 1, NULL);
	}
	
}

void get_peer_certificate(tls_daemon_ctx_t* ctx, unsigned long id, tls_conn_ctx_t* tls_conn) {

	unsigned long * idp;

	/* Connect if we're not connected. 
	 * This is only needed because we don't explicitly call it
	 * during the connection, to support OpenSSL overriding */
	if (SSL_in_init(tls_conn->tls)) {
		idp = malloc(sizeof(id));
		*idp = id;
		SSL_set_ex_data(tls_conn->tls, OPENSSL_EX_DATA_ID, idp);
		SSL_set_ex_data(tls_conn->tls, OPENSSL_EX_DATA_CTX, ctx);
		SSL_set_info_callback(tls_conn->tls, certificate_handshake_cb);
		SSL_do_handshake(tls_conn->tls);
		return;
	}

	/* If we have already completed the handshake we do not 
	 * need to register a callback and can get the certificate
	 * imediataly  */
	peer_certificate_cb(ctx,id,tls_conn->tls);

	return;
}

int server_name_cb(SSL* tls, int* ad, void* arg) {
	/* Here is where we'd do anything needed for handling
	 * connections differently based on SNI  */
	return SSL_TLSEXT_ERR_OK;
}

SSL* tls_client_setup(SSL_CTX* tls_ctx, char* hostname) {
	SSL* tls;

	tls = SSL_new(tls_ctx);
	//SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		return NULL;
	}

	/* set server name indication for client hello */
	if (hostname != NULL) {
		SSL_set_tlsext_host_name(tls, hostname);
	}

	return tls;
}

SSL* tls_server_setup(SSL_CTX* tls_ctx) {
	SSL* tls = SSL_new(tls_ctx);
	//SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		return NULL;
	}
	return tls;
}

void tls_bev_write_cb(struct bufferevent *bev, void *arg) {
	//log_printf(LOG_DEBUG, "write event on bev %p\n", bev);
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	struct evbuffer* out_buf;

	if (endpoint->closed) {
		out_buf = bufferevent_get_output(bev);
		if (evbuffer_get_length(out_buf) == 0) {
			bufferevent_free(bev);
			/* Should we free anything else here? */
		}
		return;
	}

	if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint->bev, EV_READ);
	}
	return;
}

void tls_bev_read_cb(struct bufferevent *bev, void *arg) {
	//log_printf(LOG_DEBUG, "read event on bev %p\n", bev);
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	
	if (endpoint->closed) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	if (in_len == 0) {
		return;
	}

	out_buf = bufferevent_get_output(endpoint->bev);
	evbuffer_add_buffer(out_buf, in_buf);

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint->bev, EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg) {
	tls_conn_ctx_t* ctx = arg;
	unsigned long ssl_err;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	channel_t* startpoint = (bev == ctx->cf.bev) ? &ctx->cf : &ctx->sf;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_INFO, "%s endpoint connected\n", bev == ctx->cf.bev ? "client facing" : "server facing");
		//if (startpoint->connected == 1) log_printf(LOG_ERROR, "Setting connected when we shouldn't\n");
		startpoint->connected = 1;
	}
	if (events & BEV_EVENT_ERROR) {
		//log_printf(LOG_INFO, "%s endpoint encountered an error\n", bev == ctx->cf.bev ? "client facing" : "server facing");
		if (errno) {
			if (errno == ECONNRESET || errno == EPIPE) {
				log_printf(LOG_INFO, "Connection closed\n");
				startpoint->closed = 1;
			}
			else {
				log_printf(LOG_INFO, "An unhandled error has occurred\n");
			}
		}
		while ((ssl_err = bufferevent_get_openssl_error(bev))) {
			log_printf(LOG_ERROR, "SSL error from bufferevent: %s [%s]\n", 
					ERR_func_error_string(ssl_err), ERR_reason_error_string(ssl_err));
		}
		if (endpoint->closed == 0) {
			struct evbuffer* out_buf;
			out_buf = bufferevent_get_output(endpoint->bev);
			/* close other buffer if we're closing and it has no data left */
			if (evbuffer_get_length(out_buf) == 0) {
				endpoint->closed = 1;
			}
		}
		/* always close startpoint on unhandled error */
		startpoint->closed = 1;

	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "%s endpoint got EOF\n", bev == ctx->cf.bev ? "client facing" : "server facing");
		if (endpoint->closed == 0) {
			struct evbuffer* in_buf;
			struct evbuffer* out_buf;
			out_buf = bufferevent_get_output(endpoint->bev);
			in_buf = bufferevent_get_input(bev);
			if (evbuffer_get_length(in_buf) > 0) {
				evbuffer_add_buffer(out_buf, in_buf);
			}
			if (evbuffer_get_length(out_buf) == 0) {
				endpoint->closed = 1;
			}
		}
		/* always close the startpoint on EOF */
		startpoint->closed = 1;
	}
	/* If both channels are closed now, free everything */
	if (endpoint->closed == 1 && startpoint->closed == 1) {
		free_tls_conn_ctx(ctx);
	}
	return;
}

tls_conn_ctx_t* new_tls_conn_ctx() {
	tls_conn_ctx_t* ctx = (tls_conn_ctx_t*)calloc(1, sizeof(tls_conn_ctx_t));
	return ctx;
}

void free_tls_conn_ctx(tls_conn_ctx_t* ctx) {
	if (ctx == NULL) return;
	/* Line below seems to be handled by bufferevent_free */
	if (ctx->tls != NULL) {
		SSL_shutdown(ctx->tls);
	}
	if (ctx->cf.bev != NULL) bufferevent_free(ctx->cf.bev);
	if (ctx->sf.bev != NULL) bufferevent_free(ctx->sf.bev);
	free(ctx);
	return;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* The following is lifted from the OpenSSL codebase.
 * This function was added in OpenSSL 1.1 */
static int use_certificate_chain_file(SSL_CTX *ctx, SSL *ssl, const char *file)
{
    BIO *in;
    int ret = 0;
    X509 *x = NULL;
    pem_password_cb *passwd_callback;
    void *passwd_callback_userdata;

    ERR_clear_error();          /* clear error stack for
                                 * SSL_CTX_use_certificate() */

    if (ctx != NULL) {
        passwd_callback = ctx->default_passwd_callback;
        passwd_callback_userdata = ctx->default_passwd_callback_userdata;
    } else {
        passwd_callback = ssl->default_passwd_callback;
        passwd_callback_userdata = ssl->default_passwd_callback_userdata;
    }

    in = BIO_new(BIO_s_file());
    if (in == NULL) {
        SSLerr(SSL_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, passwd_callback,
                              passwd_callback_userdata);
    if (x == NULL) {
        SSLerr(SSL_F_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    if (ctx)
        ret = SSL_CTX_use_certificate(ctx, x);
    else
        ret = SSL_use_certificate(ssl, x);

    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        if (ctx)
            r = SSL_CTX_clear_chain_certs(ctx);
        else
            r = SSL_clear_chain_certs(ssl);

        if (r == 0) {
            ret = 0;
            goto end;
        }

        while ((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
                                       passwd_callback_userdata))
               != NULL) {
            if (ctx)
                r = SSL_CTX_add0_chain_cert(ctx, ca);
            else
                r = SSL_add0_chain_cert(ssl, ca);
            /*
             * Note that we must not free ca if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by SSL_CTX_use_certificate).
             */
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }

 end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int SSL_use_certificate_chain_file(SSL *ssl, const char *file) {
	return use_certificate_chain_file(NULL, ssl, file);
}
#endif
