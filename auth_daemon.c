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
#include <event2/buffer.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "auth_daemon.h"
#include "log.h"
#include "nsd.h"

#ifdef CLIENT_AUTH
#include "notification.h"
#endif //CLIENT_AUTH

#define HALF_SEC_USEC	50000
#define MAX_UNIX_NAME	256

typedef struct auth_daemon_ctx {
	struct event_base* ev_base;
	struct evconnlistener* device_listener;
	struct bufferevent* device_bev;
	struct evconnlistener* worker_listener;
	struct bufferevent* worker_bev;
	SSL_CTX *tls_ctx;
	int qrcode_gui_pid;
	char connection_status;
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
static void unencrypted_write_cb(struct bufferevent *bev, void *arg);
static void log_close_cb(struct bufferevent *bev, void *arg);
static void device_read_cb(struct bufferevent *bev, void *arg);
static void device_event_cb(struct bufferevent *bev, short events, void *arg);
static void unencrypted_read_cb(struct bufferevent *bev, void *arg);
//static void qrpopup_cb(int fd, short event, void *arg);

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
	daemon_ctx.qrcode_gui_pid = 0;
	daemon_ctx.connection_status = AVAILABLE;

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
	struct evbuffer * out_buf;
	char byte;

	log_printf(LOG_DEBUG, "requester_read_cb called. Computer is %s(%d)\n",
			ctx->connection_status?"AVAILABLE":"CONNECTED",
			ctx->connection_status);


	if (ctx->device_bev == 0) {
		byte  = FAILURE_RESPONSE;
		out_buf = bufferevent_get_output(bev);
		evbuffer_add(out_buf, (void*)&byte, sizeof(char));
		log_printf(LOG_INFO, "requester_read_cb invoked with device disconnected\n");
#if CLIENT_AUTH
		connect_phone_alert();
#endif
		return;
	}
	log_printf(LOG_DEBUG, "buffer has %d bytes to reed\n",
		evbuffer_get_length(bufferevent_get_output(ctx->device_bev)));
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
	struct evbuffer* out_buf;
	char byte;

	auth_daemon_ctx_t* ctx = arg;

	log_printf(LOG_INFO, "A new authentication device has registered. Computer is %s(%d)\n",
			ctx->connection_status?"AVAILABLE":"CONNECTED",
			ctx->connection_status);

	struct bufferevent* bev = bufferevent_socket_new(ctx->ev_base, fd,
				BEV_OPT_DEFER_CALLBACKS);

	/* Put a byte in the buffer */
	//evconnlistener_disable(listener);
	out_buf = bufferevent_get_output(bev);
	bufferevent_setwatermark(bev, BEV_EVENT_WRITING | BEV_EVENT_READING, 1, 1);

	if (ctx->connection_status == AVAILABLE) {
		byte = AVAILABLE;
		evbuffer_add(out_buf, (void*)&byte, sizeof(char));
		bufferevent_setcb(bev, unencrypted_read_cb, unencrypted_write_cb, NULL, arg);
		bufferevent_enable(bev, EV_WRITE);
		ctx->connection_status = CONNECTED;
	}
	else {
		byte = CONNECTED;
		evbuffer_add(out_buf, (void*)&byte, sizeof(char));
		bufferevent_setcb(bev, NULL, log_close_cb, NULL, arg);
		bufferevent_enable(bev, EV_WRITE);
	}
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

	log_printf(LOG_DEBUG, "Device_event_cb called with event %#x %s%s%s%s%s%s\n",
			events,

			events & BEV_EVENT_READING?"(BEV_EVENT_READING)":"",
			events & BEV_EVENT_WRITING?"(BEV_EVENT_WRITING)":"",
			events & BEV_EVENT_EOF?"(BEV_EVENT_EOF)":"",

			events & BEV_EVENT_ERROR?"(BEV_EVENT_ERROR)":"",
			events & BEV_EVENT_TIMEOUT?"(BEV_EVENT_TIMEOUT)":"",
			events & BEV_EVENT_CONNECTED?"(BEV_EVENT_CONNECTED)":""
		  );

	if (events & BEV_EVENT_CONNECTED) {
		if (ctx->qrcode_gui_pid > 0) {
			log_printf(LOG_DEBUG, "Cliant connected. QRCode signaled to close\n");
			kill(ctx->qrcode_gui_pid, SIGUSR1);
			ctx->qrcode_gui_pid = 0;
		}
	}
	if (events & BEV_EVENT_EOF) {
		log_printf(LOG_INFO, "Authentication device disconnecting, Computer is %s(%d)\n",
			ctx->connection_status?"AVAILABLE":"CONNECTED",
			ctx->connection_status);
		//evconnlistener_enable(ctx->device_listener);
		ctx->connection_status = AVAILABLE;
		ctx->device_bev = NULL;
		bufferevent_free(bev);
	}
	if (events & BEV_EVENT_ERROR) {
		log_printf(LOG_INFO,
			"Authentication device error,  Computer is %s(%d)\n",
			ctx->connection_status?"AVAILABLE":"CONNECTED",
			ctx->connection_status);
		//evconnlistener_enable(ctx->device_listener);
		ctx->connection_status = AVAILABLE;
		ctx->device_bev = NULL;
		while ((ssl_err = bufferevent_get_openssl_error(bev))) {
			log_printf(LOG_ERROR, "SSL error from bufferevent: %s [%s]\n",
				ERR_func_error_string(ssl_err),
				 ERR_reason_error_string(ssl_err));
		}
		bufferevent_free(bev);
		if (ctx->qrcode_gui_pid > 0) {
			log_printf(LOG_DEBUG, "Connection error. QRCode signaled to closed\n");
			kill(ctx->qrcode_gui_pid, SIGUSR2);
			ctx->qrcode_gui_pid = 0;
		}
	}
	return;
}

void launch_qrpopup(auth_daemon_ctx_t *ctx) {
	int pid;
	char* const params[] = {POPUP_EXE, NULL};
	//struct timeval half_second = {0, HALF_SEC_USEC};
	//struct event *ev;

	if (ctx->qrcode_gui_pid > 0) {
		kill(ctx->qrcode_gui_pid, SIGALRM);
	}
	if ((pid = fork())) {
		log_printf(LOG_DEBUG,
			   "QrCode pop-up launched as prosses %d\n",
			   pid);
		ctx->qrcode_gui_pid = pid;
		if (pid < 0) {
			log_printf(LOG_ERROR, "qrCode fork error\n");
		}
	} else {
		execv(POPUP_EXE, params);
		exit(-1);
	}
}

void unencrypted_read_cb(struct bufferevent *bev, void *arg) {
	auth_daemon_ctx_t *ctx;
	SSL *tls;
	struct evbuffer* in_buf;
	size_t in_len;
	char data;
	int fd;

	ctx = (auth_daemon_ctx_t*)arg;
	in_buf = bufferevent_get_input(bev);
	in_len = evbuffer_get_length(in_buf);
	evbuffer_remove(in_buf, &data, 1);

	log_printf(LOG_DEBUG,
		  "Qrpopup_read_cb called. %d byte(s) to read (%#x), %s\n",
		  in_len, data,
		  data==1?"QR code will launch":"QR code will not launch");

	if (in_len && data == 1) {
		launch_qrpopup(ctx);
	}
	
	fd = bufferevent_getfd(bev);
	bufferevent_free(bev);

	tls = SSL_new(ctx->tls_ctx);
	bev = bufferevent_openssl_socket_new(ctx->ev_base, fd,
			tls, BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	ctx->device_bev = bev;
	bufferevent_setcb(bev, device_read_cb, device_write_cb, device_event_cb, ctx);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	return;
}

static void unencrypted_write_cb(struct bufferevent *bev, void *arg) {
	//auth_daemon_ctx_t* ctx = (auth_daemon_ctx_t*) arg;

	log_printf(LOG_DEBUG, "Ready status sent\n");

	bufferevent_enable(bev, EV_READ);
}

static void log_close_cb(struct bufferevent *bev, void *arg) {
	//auth_daemon_ctx_t* ctx = (auth_daemon_ctx_t*) arg;

	log_printf(LOG_DEBUG, "Connection status=busy -> Socket closed\n");

	evutil_closesocket(bufferevent_getfd(bev));
	bufferevent_free(bev);
}
