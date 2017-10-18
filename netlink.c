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

#include <event2/util.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "netlink.h"

struct nl_sock* netlink_connect(void) {
	int group;
	int family;
	struct nl_sock* netlink_sock = nl_socket_alloc();
	nl_socket_set_local_port(netlink_sock, 0);
	nl_socket_disable_seq_check(netlink_sock);
	//nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, recv_response_cb, (void*)netlink_sock);
	if (netlink_sock == NULL) {
		fprintf(stderr, "Failed to allocate socket\n");
		return NULL;
	}

	if (genl_connect(netlink_sock) != 0) {
		fprintf(stderr, "Failed to connect to Generic Netlink control\n");
		return NULL;
	}

	if ((family = genl_ctrl_resolve(netlink_sock, "SSA")) < 0) {
		fprintf(stderr, "Failed to resolve SSA family identifier\n");
		return NULL;
	}

	if ((group = genl_ctrl_resolve_grp(netlink_sock, "SSA", "notify")) < 0) {
		fprintf(stderr, "Failed to resolve group identifier\n");
		return NULL;
	}

	if (nl_socket_add_membership(netlink_sock, group) < 0) {
		fprintf(stderr, "Failed to add membership to group\n");
		return NULL;
	}
	return 0;
}

void netlink_recv(evutil_socket_t fd, short events, void *arg) {
	printf("Got a message from the kernel!");
	return;
}

int netlink_disconnect(struct nl_sock* sock) {
        nl_socket_free(sock);
        return 0;
}
