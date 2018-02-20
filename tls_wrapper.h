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
#ifndef TLS_WRAPPER_H
#define TLS_WRAPPER_H
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>
#include <netinet/in.h>

#include <openssl/ssl.h>

#include "daemon.h"

typedef struct channel {
	struct bufferevent* bev;
	int closed;
	int connected;
} channel_t;

typedef struct tls_conn_ctx {
	channel_t cf;
	channel_t sf;
	SSL* tls;
} tls_conn_ctx_t;

tls_conn_ctx_t* tls_client_wrapper_setup(evutil_socket_t ifd, evutil_socket_t efd, 
	struct event_base* ev_base, char* hostname, int is_accepting, SSL* s_ctx);
tls_conn_ctx_t* tls_server_wrapper_setup(evutil_socket_t efd, evutil_socket_t ifd,
	       	struct event_base* ev_base, SSL_CTX* tls_ctx, 
		struct sockaddr* internal_addr, int internal_addrlen);


/* Helper functions to separate daemon from security library */
void get_peer_certificate(tls_daemon_ctx_t* ctx, unsigned long id, tls_conn_ctx_t* tls_conn);
int set_private_key(SSL_CTX* tls_ctx, char* filepath);
int set_certificate_chain(SSL_CTX* tls_ctx, char* filepath);
int set_hostname(tls_conn_ctx_t* tls_conn_ctx, char* hostname);
SSL_CTX* tls_server_ctx_create(void);
#endif
