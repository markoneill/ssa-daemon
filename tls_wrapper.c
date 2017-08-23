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

void tls_wrapper_setup(evutil_socket_t fd, struct event_base* ev_base,  
	struct sockaddr* client_addr, int client_addrlen,
	struct sockaddr* server_addr, int server_addrlen, char* hostname) {
	
	struct bufferevent* bev_client_facing;
	struct bufferevent* bev_server_facing;
	SSL* tls;

	bev_client_facing = bufferevent_socket_new(ev_base, fd,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (bev_client_facing == NULL) {
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent\n");
		return;
	}

	/* Set up SSL state */
	log_printf(LOG_DEBUG, "ev_base is %p and host is %s (%p)\n", ev_base, hostname, hostname);
	tls = tls_create(hostname);
	if (tls == NULL) {
		log_printf(LOG_ERROR, "Failed to set up TLS (SSL*) context\n");
		return;
	}

	bev_server_facing = bufferevent_openssl_socket_new(ev_base, -1, tls,
		BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (bev_server_facing == NULL) {
		EVUTIL_CLOSESOCKET(fd);
		log_printf(LOG_ERROR, "Failed to set up client facing bufferevent\n");
		return;
	}
	/* Comment out this line if you need to do better debugging of OpenSSL behavior */
	#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(bev_server_facing, 1);
	#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	/* Connect server facing socket */
	if (bufferevent_socket_connect(bev_server_facing, (struct sockaddr*)server_addr, server_addrlen) < 0) {
		log_printf(LOG_ERROR, "bufferevent_socket_connect: %s\n", strerror(errno));
		bufferevent_free(bev_server_facing);
		bufferevent_free(bev_client_facing);
		return;
	}

	/* Register callbacks for reading and writing to both bevs */
	bufferevent_setcb(bev_server_facing, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, bev_client_facing);
	bufferevent_enable(bev_server_facing, EV_READ | EV_WRITE);
	bufferevent_setcb(bev_client_facing, tls_bev_read_cb, tls_bev_write_cb, tls_bev_event_cb, bev_server_facing);
	bufferevent_enable(bev_client_facing, EV_READ | EV_WRITE);

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
	struct bufferevent* endpoint = arg;
	struct evbuffer* out_buf;

	/* XXX Need a way to do this only when remote is closed */
	/*out_buf = bufferevent_get_output(bev);
	if (evbuffer_get_length(out_buf) == 0) {
		bufferevent_free(bev);
	}*/

	if (endpoint && !(bufferevent_get_enabled(endpoint) & EV_READ)) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(endpoint, EV_READ);
	}
	return;
}

void tls_bev_read_cb(struct bufferevent *bev, void *arg) {
	struct bufferevent* endpoint = arg;
	struct evbuffer* in_buf;
	struct evbuffer* out_buf;
	size_t in_len;

	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	if (in_len == 0) {
		return;
	}

	if (endpoint == NULL) {
		evbuffer_drain(in_buf, in_len);
		return;
	}

	out_buf = bufferevent_get_output(endpoint);
	evbuffer_add_buffer(out_buf, in_buf);

	if (evbuffer_get_length(out_buf) >= MAX_BUFFER) {
		log_printf(LOG_DEBUG, "Overflowing buffer, slowing down\n");
		bufferevent_setwatermark(endpoint, EV_WRITE, MAX_BUFFER / 2, MAX_BUFFER);
		bufferevent_disable(bev, EV_READ);
	}
	return;
}

void tls_bev_event_cb(struct bufferevent *bev, short events, void *arg) {
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_INFO, "Connected\n");
	}
	if (events & BEV_EVENT_ERROR) {
		log_printf(LOG_INFO, "An error has occurred\n");
		unsigned long ssl_err;
		ssl_err = bufferevent_get_openssl_error(bev);
		if (!ssl_err) {
			log_printf(LOG_ERROR, "Error from bufferevent: %s\n", strerror(errno));
		}
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "An EOF has occurred\n");
		/* XXX */
	}
	return;
}


