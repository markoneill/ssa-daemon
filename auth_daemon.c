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
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "auth_daemon.h"
#include "log.h"
#include "nsd.h"

#define QR_SHOW		0
#define QR_NO_SHOW	-1
#define HALF_SEC_USEC	5000
#define MAX_UNIX_NAME	256

typedef struct auth_daemon_ctx {
	struct event_base* ev_base;
	struct evconnlistener* device_listener;
	struct bufferevent* device_bev;
	struct evconnlistener* worker_listener;
	struct bufferevent* worker_bev;
	SSL_CTX *tls_ctx;
	int qrcode_gui_pid;
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
static void requester_write_cb(struct bufferevent *bev, void *arg);
static void requester_read_cb(struct bufferevent *bev, void *arg);
static void requester_event_cb(struct bufferevent *bev, short events, void *arg);

void new_device_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg);
void new_device_error_cb(struct evconnlistener *listener, void *ctx);
static void device_write_cb(struct bufferevent *bev, void *arg);
static void device_read_cb(struct bufferevent *bev, void *arg);
static void device_event_cb(struct bufferevent *bev, short events, void *arg);
void qrpopup_cb(int fd, short event, void *arg);

void auth_server_create(int port, X509* cert, EVP_PKEY *pkey) {
	auth_daemon_ctx_t daemon_ctx;
	struct event_base* ev_base;

	char unix_id[] = "\0auth_req";
	struct evconnlistener* ipc_listener;
	struct sockaddr_un ipc_addr;
	int ipc_addrlen;

	struct evconnlistener* ext_listener;
	struct sockaddr_in ext_addr;
	int ext_addrlen;

	SSL_CTX *new_tls_ctx;
	ev_base = event_base_new(); /* Set up listener for IPC from SSA workers */
	memset(&ipc_addr, 0, sizeof(struct sockaddr_un));
	ipc_addr.sun_family = AF_UNIX;
	memcpy(ipc_addr.sun_path, unix_id, sizeof(unix_id));
	ipc_addrlen = sizeof(sa_family_t) + sizeof(unix_id);
	ipc_listener = evconnlistener_new_bind(ev_base, new_requester_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE, SOMAXCONN,
		(struct sockaddr*)&ipc_addr, ipc_addrlen);
	if (ipc_listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create ipc listener\n");
		return;
	}
	evconnlistener_set_error_cb(ipc_listener, new_requester_error_cb);

	/* Set up listener for external authentication devices */
	memset(&ext_addr, 0, sizeof(struct sockaddr_in));
	ext_addr.sin_family = AF_INET;
	ext_addr.sin_port = htons(port);
	ext_addr.sin_addr.s_addr = htonl(0);
	ext_addrlen = sizeof(ext_addr);
	ext_listener = evconnlistener_new_bind(ev_base, new_device_cb, &daemon_ctx, 
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_THREADSAFE | LEV_OPT_REUSEABLE, SOMAXCONN,
		(struct sockaddr*)&ext_addr, ext_addrlen);
	if (ext_listener == NULL) {
		log_printf(LOG_ERROR, "Couldn't create auth device listener\n");
		return;
	}
	evconnlistener_set_error_cb(ext_listener, new_device_error_cb);

	new_tls_ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_use_PrivateKey(new_tls_ctx, pkey);
        SSL_CTX_use_certificate(new_tls_ctx, cert);

	daemon_ctx.tls_ctx = new_tls_ctx;
	daemon_ctx.ev_base = ev_base;
	daemon_ctx.worker_listener = ipc_listener;
	daemon_ctx.worker_bev = NULL;
	daemon_ctx.device_listener = ext_listener;
	daemon_ctx.device_bev = NULL;

	log_printf(LOG_INFO, "Starting auth daemon\n");
	event_base_dispatch(ev_base);

	evconnlistener_free(ipc_listener); 
	evconnlistener_free(ext_listener); 
        event_base_free(ev_base);
	return;
}

void new_requester_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	log_printf(LOG_INFO, "Worker requesting auth services\n");
	
	auth_daemon_ctx_t* ctx = arg;
	evconnlistener_disable(listener);
	struct bufferevent* bev = bufferevent_socket_new(ctx->ev_base, fd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	ctx->worker_bev = bev;
	bufferevent_setcb(bev, requester_read_cb, requester_write_cb, requester_event_cb, ctx);
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

void requester_write_cb(struct bufferevent *bev, void *arg) {
	return;
}

void requester_read_cb(struct bufferevent *bev, void *arg) {
	auth_daemon_ctx_t* ctx = arg;

	if (ctx->device_bev == 0) {
		log_printf(LOG_INFO, "requester_read_cb invoked with device disconnected\n");
		return;
	}
	bufferevent_read_buffer(bev, 
			bufferevent_get_output(ctx->device_bev));
	return;
	/*request_info_t* ri = (request_info_t*)arg;
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
	}*/
	return;
}

void requester_event_cb(struct bufferevent *bev, short events, void *arg) {
	auth_daemon_ctx_t* ctx = arg;
	if (events & BEV_EVENT_CONNECTED) {
		log_printf(LOG_INFO, "Worker connecting\n");
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "Worker disconnecting\n");
		evconnlistener_enable(ctx->worker_listener);
		ctx->worker_bev = NULL;
		bufferevent_free(bev);
	}
	if (events & BEV_EVENT_ERROR) {
		evconnlistener_enable(ctx->worker_listener);
		ctx->worker_bev = NULL;
		bufferevent_free(bev);
	}
	return;
}

void new_device_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *address, int socklen, void *arg) {
	struct event *ev;
	struct timeval half_second = {0, HALF_SEC_USEC};
	SSL *tls;

	log_printf(LOG_INFO, "A new authentication device has registered\n");
	
	auth_daemon_ctx_t* ctx = arg;
	evconnlistener_disable(listener);
	tls = SSL_new(ctx->tls_ctx);
	struct bufferevent* bev = bufferevent_openssl_socket_new(ctx->ev_base, fd,
			tls, BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	// ************************************************************************
	// code to display a QR code image
	//
	
	ctx->qrcode_gui_pid = QR_SHOW;
	ev = event_new(ctx->ev_base, -1, EV_TIMEOUT, qrpopup_cb, ctx);
	event_add(ev, &half_second);

	ctx->device_bev = bev;
	bufferevent_setcb(bev, device_read_cb, device_write_cb, device_event_cb, ctx);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	return;
}

void new_device_error_cb(struct evconnlistener *listener, void *ctx) {
        struct event_base *base = evconnlistener_get_base(listener);
        int err = EVUTIL_SOCKET_ERROR();
        log_printf(LOG_ERROR, "Got an error %d (%s) on the listener\n", 
				err, evutil_socket_error_to_string(err));
        event_base_loopexit(base, NULL);
	return;
}

void device_write_cb(struct bufferevent *bev, void *arg) {
	return;
}

void device_read_cb(struct bufferevent *bev, void *arg) {
	auth_daemon_ctx_t* ctx = arg;

	if (ctx->worker_bev == 0) {
		log_printf(LOG_INFO, "device_read_cb invoked with worker disconnected\n");
		return;
	}
	bufferevent_read_buffer(bev, 
			bufferevent_get_output(ctx->worker_bev));
	return;
}

void device_event_cb(struct bufferevent *bev, short events, void *arg) {
	auth_daemon_ctx_t* ctx = arg;
	int ssl_err;

	log_printf(LOG_DEBUG, "device_event_cb called with event %d (%s%s%s)",
			events,
			events & BEV_EVENT_CONNECTED?"BEV_EVENT_CONNECTED":"",
			events & BEV_EVENT_EOF?"BEV_EVENT_EOF":"",
			events & BEV_EVENT_ERROR?"BEV_EVENT_ERROR":"");

	if (events & BEV_EVENT_CONNECTED) {
		if (ctx->qrcode_gui_pid > 0) {
			log_printf(LOG_DEBUG, "connected. QRCode closed\n");
			kill(ctx->qrcode_gui_pid, SIGUSR1);
			ctx->qrcode_gui_pid = QR_NO_SHOW;
		}
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "Authentication device disconnecting\n");
		evconnlistener_enable(ctx->device_listener);
		ctx->device_bev = NULL;
		bufferevent_free(bev);
	}
	if (events & BEV_EVENT_ERROR) {
		log_printf(LOG_INFO, "Authentication device error\n");
		evconnlistener_enable(ctx->device_listener);
		ctx->device_bev = NULL;
		while ((ssl_err = bufferevent_get_openssl_error(bev))) {
			log_printf(LOG_ERROR, "SSL error from bufferevent: %s [%s]\n",
				ERR_func_error_string(ssl_err),
				 ERR_reason_error_string(ssl_err));
		}
		bufferevent_free(bev);
		if (ctx->qrcode_gui_pid > 0) {
			log_printf(LOG_DEBUG, "error. QRCode closed\n");
			kill(ctx->qrcode_gui_pid, SIGUSR2);
			ctx->qrcode_gui_pid = QR_NO_SHOW;
		}
	}
	return;
}

void qrpopup_cb(int fd, short event, void *arg) {
	auth_daemon_ctx_t *ctx = arg;
	char* const params[] = {POPUP_EXE, NULL};
	int pid;

	log_printf(LOG_DEBUG, "qrpoput_cb called with fd: %d event: %h\n", fd, event);

	if (ctx->qrcode_gui_pid == QR_SHOW) {
		if ((pid = fork())) {
			log_printf(LOG_INFO, "qrCode pop-up launched\n");
		} else {
			execv(POPUP_EXE, params);
			exit(-1);
		}
		ctx->qrcode_gui_pid = pid;
	}
}
