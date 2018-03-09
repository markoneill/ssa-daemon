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


#define MAX_HOSTNAME		255

typedef struct tls_daemon_ctx {
	struct event_base* ev_base;
	struct nl_sock* netlink_sock;
	int netlink_family;
	int port; /* Port to use for both listening and netlink */
	hmap_t* sock_map;
	hmap_t* sock_map_port;
} tls_daemon_ctx_t;

int server_create(int port);
void socket_cb(tls_daemon_ctx_t* ctx, unsigned long id, char* comm);
void setsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, 
		int option, void* value, socklen_t len);
void getsockopt_cb(tls_daemon_ctx_t* ctx, unsigned long id, int level, int option);
void bind_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);
void connect_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen, struct sockaddr* rem_addr, int rem_addrlen, int blocking);
void listen_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
	int int_addrlen, struct sockaddr* ext_addr, int ext_addrlen);
void associate_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr,
	       	int int_addrlen);
void close_cb(tls_daemon_ctx_t* ctx, unsigned long id);
void upgrade_cb(tls_daemon_ctx_t* ctx, unsigned long id, struct sockaddr* int_addr, 
	int int_addrlen);

#endif
