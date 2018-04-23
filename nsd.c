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
#include "nsd.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>

typedef struct service_ctx {
	AvahiClient* client;
	AvahiEntryGroup* group;
	AvahiSimplePoll* poller;
	int port;
} service_ctx_t;

static int publish_service(service_ctx_t* ctx);
static void client_cb(AvahiClient* client, AvahiClientState state, void* userdata);
static void entry_group_cb(AvahiEntryGroup* group, AvahiEntryGroupState state, void* userdata);

/*int main() {
	if (log_init(NULL, LOG_DEBUG)) {
		fprintf(stderr, "Failed to initialize log\n");
		exit(EXIT_FAILURE);
	}
	register_auth_service();
	log_close();
	return 0;
}*/

int register_auth_service(int port) {
	int err;
	service_ctx_t* ctx;
	AvahiClientFlags flags = 0;

	ctx = calloc(1, sizeof(service_ctx_t));

	ctx->port = port;
	ctx->poller = avahi_simple_poll_new();
	if (ctx->poller == NULL) {
		log_printf(LOG_ERROR, "Avahi Error: couldn't create poller\n");
		return 0;
	}

	ctx->client = avahi_client_new(avahi_simple_poll_get(ctx->poller), flags,
		 client_cb, ctx, &err);
	if (ctx->client == NULL) {
		log_printf(LOG_ERROR, "Avahi Error: %s\n", avahi_strerror(err));
		return 0;
	}

	avahi_simple_poll_loop(ctx->poller);
	
	avahi_client_free(ctx->client);
	avahi_simple_poll_free(ctx->poller);
	free(ctx);
	return 1;
}

int publish_service(service_ctx_t* ctx) {
	int err;
	if (ctx->group == NULL) {
		ctx->group = avahi_entry_group_new(ctx->client, entry_group_cb, ctx);
		if (ctx->group == NULL) {
			log_printf(LOG_ERROR, "Avahi Error: %s\n", 
				avahi_strerror(avahi_client_errno(ctx->client)));
			return 0;
		}
	}

	if (avahi_entry_group_is_empty(ctx->group)) {
		err = avahi_entry_group_add_service(ctx->group, 
			AVAHI_IF_UNSPEC, /* announce on all interfaces */
			AVAHI_PROTO_UNSPEC, /* announce on all protocols */
			0,
			"SSA Auth",
			"_auth._tcp",
			NULL, /* daemon will decide domain */
			NULL, /* daemon will decide hostname */
			ctx->port, /* service port */
			NULL /* Null-terminated list of additional TXT records */
		);
		if (err < 0) {
			log_printf(LOG_ERROR, "Avahi Error: %s\n", avahi_strerror(err));
			return 0;
		}
	}

	if (avahi_entry_group_commit(ctx->group) < 0) {
		log_printf(LOG_ERROR, "Avahi Error: %s\n", avahi_strerror(err));
		return 0;
	}
	return 1;
}

void client_cb(AvahiClient* client, AvahiClientState state, void* userdata) {
	service_ctx_t* ctx = userdata;
	if (ctx->client == NULL) {
		ctx->client = client;
	}
	switch (state) {
		case AVAHI_CLIENT_S_RUNNING:
			publish_service(ctx);
			break;
		case AVAHI_CLIENT_FAILURE:
			log_printf(LOG_ERROR, "Avahi Error: %s\n", 
				avahi_strerror(avahi_client_errno(client)));
			avahi_simple_poll_quit(ctx->poller);
			break;
		case AVAHI_CLIENT_S_COLLISION:
		case AVAHI_CLIENT_S_REGISTERING:
			if (ctx->group) {
				avahi_entry_group_reset(ctx->group);
			}
			break;
		case AVAHI_CLIENT_CONNECTING:
		default:
			break;
	}
	return;
}

void entry_group_cb(AvahiEntryGroup* group, AvahiEntryGroupState state, AVAHI_GCC_UNUSED void* userdata) {
	service_ctx_t* ctx = userdata;
	switch (state) {
		case AVAHI_ENTRY_GROUP_ESTABLISHED:
			log_printf(LOG_INFO, "SSA service published\n");
			break;
		case AVAHI_ENTRY_GROUP_FAILURE:
		case AVAHI_ENTRY_GROUP_COLLISION:
			log_printf(LOG_ERROR, "Avahi Error: %s\n", 
				avahi_strerror(avahi_client_errno(ctx->client)));
			avahi_simple_poll_quit(ctx->poller);
			break;
		case AVAHI_ENTRY_GROUP_REGISTERING:
		case AVAHI_ENTRY_GROUP_UNCOMMITED:
		default:
			break;
	}
	return;
}

