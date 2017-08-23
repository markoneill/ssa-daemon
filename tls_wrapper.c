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

#define MAX_BUFFER	1024*1024

static SSL* tls_create(char* hostname);
static void tls_bev_write_cb(struct bufferevent *bev, void *arg);
static void tls_bev_read_cb(struct bufferevent *bev, void *arg);
static void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg);

static tls_conn_ctx_t* new_tls_conn_ctx();
static void free_tls_conn_ctx(tls_conn_ctx_t* ctx);

void tls_wrapper_setup(evutil_socket_t fd, struct event_base* ev_base,  
	struct sockaddr* client_addr, int client_addrlen,
	struct sockaddr* server_addr, int server_addrlen, char* hostname) {
	
	tls_conn_ctx_t* ctx = new_tls_conn_ctx();
	if (ctx == NULL) {
		log_printf(LOG_ERROR, "Failed to allocate tls_conn_ctx_t: %s\n", strerror(errno));
		return;
	}

	ctx->cf.bev = bufferevent_socket_new(ev_base, fd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (ctx->cf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent\n");
		/* Need to close socket because it won't be closed on free since bev creation failed */
		EVUTIL_CLOSESOCKET(fd);
		free_tls_conn_ctx(ctx);
		return;
	}

	/* Set up TLS/SSL state with openssl */
	ctx->tls = tls_create(hostname);
	if (ctx->tls == NULL) {
		log_printf(LOG_ERROR, "Failed to set up TLS (SSL*) context\n");
		free_tls_conn_ctx(ctx);
		return;
	}

	ctx->sf.bev = bufferevent_openssl_socket_new(ev_base, -1, ctx->tls,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (ctx->sf.bev == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent\n");
		free_tls_conn_ctx(ctx);
		return;
	}

	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->sf.bev, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	/* Connect server facing socket */
	if (bufferevent_socket_connect(ctx->sf.bev, (struct sockaddr*)server_addr, server_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect: %s\n", strerror(errno));
		free_tls_conn_ctx(ctx);
		return;
	}

	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(ctx->sf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->sf.bev, EV_READ | EV_WRITE);
	bufferevent_setcb(ctx->cf.bev, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, ctx);
	bufferevent_enable(ctx->cf.bev, EV_READ | EV_WRITE);

	return;
}

SSL* tls_create(char* hostname) {
	SSL_CTX* tls_ctx;
	SSL* tls;

	/* Parameterize all this later XXX */
	tls_ctx = SSL_CTX_new(SSLv23_method());
	if (tls_ctx == NULL) {
		log_printf(LOG_ERROR, "Failed in SSL_CTX_new()\n");
		return NULL;
	}

	/* There's a billion options we can/should set here by admin config XXX
 	 * See SSL_CTX_set_options and SSL_CTX_set_cipher_list for details */

	/* We're going to commit the cardinal sin for a bit. Hook up TrustBase here XXX */
	SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);

	tls = SSL_new(tls_ctx);
	SSL_CTX_free(tls_ctx); /* lower reference count now in case we need to early return */
	if (tls == NULL) {
		return NULL;
	}

	/* set server name indication for client hello */
	SSL_set_tlsext_host_name(tls, hostname);


	/* Should also allow some sort of session resumption here XXX
  	 * See SSL_set_session for details  */

	return tls;
}

void tls_bev_write_cb(struct bufferevent *bev, void *arg) {
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	struct evbuffer* out_buf;

	if (endpoint->closed) {
		out_buf = bufferevent_get_output(bev);
		if (evbuffer_get_length(out_buf) == 0) {
			bufferevent_free(bev);
		}
	}

	if (endpoint->bev && !(bufferevent_get_enabled(endpoint->bev) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint->bev, EV_READ);
	}
	return;
}

void tls_bev_read_cb(struct bufferevent *bev, void *arg) {
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	if (in_len == 0) {
		return;
	}

	if (endpoint->bev == NULL) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	out_buf = bufferevent_get_output(endpoint->bev);
	if (endpoint->closed == 0) {
		evbuffer_add_buffer(out_buf, in_buf);
	}

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint->bev, EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg) {
	tls_conn_ctx_t* ctx = arg;
	channel_t* endpoint = (bev == ctx->cf.bev) ? &ctx->sf : &ctx->cf;
	channel_t* startpoint = (bev == ctx->cf.bev) ? &ctx->cf : &ctx->sf;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_INFO, "Connected\n");
		startpoint->connected = 1;
	}
	if (events & BEV_EVENT_ERROR) {
		unsigned long ssl_err;
		if (errno == ECONNRESET || errno == EPIPE) {
			log_printf(LOG_INFO, "Connection closed: %s\n", strerror(errno));
			startpoint->closed = 1;
		}
		else {
			log_printf(LOG_INFO, "An unhandled error has occurred: %s\n", strerror(errno));
		}
		/*ssl_err = bufferevent_get_openssl_error(bev);
		if (!ssl_err) {
			log_printf(LOG_ERROR, "Error from bufferevent: %s\n", strerror(errno));
		}*/
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "An EOF has occurred\n");
		bufferevent_free(startpoint->bev);
		startpoint->bev = NULL;
		startpoint->closed = 1;
	}
	return;
}


tls_conn_ctx_t* new_tls_conn_ctx() {
	tls_conn_ctx_t* ctx = (tls_conn_ctx_t*)calloc(1, sizeof(tls_conn_ctx_t));
	return ctx;
}

void free_tls_conn_ctx(tls_conn_ctx_t* ctx) {
	if (ctx == NULL) return;
	if (ctx->cf.bev != NULL) bufferevent_free(ctx->cf.bev);
	if (ctx->sf.bev != NULL) bufferevent_free(ctx->sf.bev);
	if (ctx->tls != NULL) SSL_free(ctx->tls);
	free(ctx);
	return;
}

