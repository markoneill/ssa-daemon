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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include "auth_daemon.h"
#include "log.h"
#include "nsd.h"

#define MAX_UNIX_NAME	256

typedef struct auth_daemon_ctx {
	struct event_base* ev_base;
	evutil_socket_t auth_device;
} auth_daemon_ctx_t;

enum state {
	UNREAD,
	HEADER_READ,
	DATA_READ
};

typedef struct request_info {
	char type;
	int state;
} request_info_t;

void new_requester_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg);
void new_requester_error_cb(struct evconnlistener *listener, void *ctx);
evutil_socket_t create_unix_sock(char* id);
static void auth_write_cb(struct bufferevent *bev, void *arg);
static void auth_read_cb(struct bufferevent *bev, void *arg);
static void auth_event_cb(struct bufferevent *bev, short events, void *arg);

void auth_server_create(int port) {
	struct event* auth_req_ev;
	evutil_socket_t auth_req_sock;
	struct event_base* ev_base;
	struct evconnlistener* listener;

	ev_base = event_base_new();

	auth_daemon_ctx_t daemon_ctx = {
		.ev_base = ev_base,
		.auth_device = 0
	};

	auth_req_sock = create_unix_sock("auth_req");
	listener = evconnlistener_new(ev_base, new_requester_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE, SOMAXCONN, auth_req_sock);
	if (listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create evconnlistener\n");
		return 1;
	}
	evconnlistener_set_error_cb(listener, new_requester_error_cb);

	log_printf(LOG_INFO, "Starting auth daemon\n");
	event_base_dispatch(ev_base);

	evconnlistener_free(listener); 
        event_base_free(ev_base);
	return;
}

evutil_socket_t create_unix_sock(char* id) {
	evutil_socket_t sock;
	int ret;
	struct sockaddr_un addr;
	int addrlen;
	char name[MAX_UNIX_NAME];
	int namelen = snprintf(name, MAX_UNIX_NAME, "%c%s", '\0', id);
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, name, namelen);
	addrlen = namelen + sizeof(sa_family_t);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		log_printf(LOG_ERROR, "socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	ret = evutil_make_socket_nonblocking(sock);
	if (ret == -1) {
		log_printf(LOG_ERROR, "Failed in evutil_make_socket_nonblocking: %s\n",
			 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}

	ret = bind(sock, (struct sockaddr*)&addr, addrlen);
	if (ret == -1) {
		log_printf(LOG_ERROR, "bind: %s\n", strerror(errno));
		EVUTIL_CLOSESOCKET(sock);
		exit(EXIT_FAILURE);
	}
	return sock;
}

void new_requester_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	log_printf(LOG_INFO, "Worker requesting auth services\n");
	
	auth_daemon_ctx_t* ctx = arg;
	request_info_t* ri;
	ri = (request_info_t*)calloc(1, sizeof(request_info_t));
	if (ri == NULL) {
		log_printf(LOG_ERROR, "Could not create request info\n");
		return;
	}
	ri->state = UNREAD;

	struct bufferevent* bev = bufferevent_socket_new(ctx->ev_base, fd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setwatermark(bev, EV_READ, AUTH_REQ_HEADER_SIZE, 0);
	bufferevent_setcb(bev, auth_read_cb, auth_write_cb, auth_event_cb, ri);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	return;
}

void new_requester_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void auth_write_cb(struct bufferevent *bev, void *arg) {

}

void auth_read_cb(struct bufferevent *bev, void *arg) {
	request_info_t* ri = (request_info_t*)arg;
	int bytes_wanted;
	switch (ri->state) {
		case UNREAD:
			bufferevent_read(bev, &ri->type, 1);
			bufferevent_read(bev, &bytes_wanted, sizeof(uint32_t));
			bytes_wanted = ntohl(bytes_wanted);
			bufferevent_setwatermark(bev, EV_READ, bytes_wanted, 0);
			ri->state = HEADER_READ;
			break;
		case HEADER_READ:
			break;
	}
	return;
}

void auth_event_cb(struct bufferevent *bev, short events, void *arg) {
	request_info_t* ri = (request_info_t*)arg;
	if (events & BEV_EVENT_CONNECTED) {
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "Worker disconnecting\n");
		free(ri);
		bufferevent_free(bev);
	}
	if (events & BEV_EVENT_ERROR) {
	}
	return;
}

