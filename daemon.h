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
#ifndef DAEMON_H
#define DAEMON_H

#include <netinet/in.h>

#include <event2/event.h>
#include <event2/util.h>

#include <openssl/ssl.h>

#include "hashmap.h"
#include "queue.h"

typedef struct listener_ctx {
	struct listener_ctx* next;
	struct sockaddr int_addr;
	int int_addrlen;
	struct sockaddr ext_addr;
	int ext_addrlen;
	evutil_socket_t socket;
	SSL_CTX* tls_ctx;
	struct evconnlistener* listener;
} listener_ctx_t;

typedef struct tls_daemon_ctx {
	struct event_base* ev_base;
	struct event* sev_pipe;
	struct nl_sock* netlink_sock;
	int netlink_family;
	listener_ctx_t* listeners;
	hmap_t* sock_map;
	hmap_t* sock_map_port;
} tls_daemon_ctx_t;

struct host_addr { 
        unsigned char name[255]; 
}; 
 
struct sockaddr_host { 
        sa_family_t sin_family; 
        unsigned short sin_port; 
        struct host_addr sin_addr; 
}; 

int server_create(void);
void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id);
void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, 
		int option, void* value, socklen_t len);
void bind_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);
void connect_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen);
void listen_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);
void close_cb(tls_daemon_ctx_t* ctx, unsigned long id);

#endif
