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
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <string.h>
#include "log.h"

#ifndef NO_LOG
FILE* g_log_file = NULL;
log_level_t g_log_level = LOG_DEBUG;

void level_printf(log_level_t level);

int log_init(const char* log_filename, log_level_t level) {
	FILE* new_log_file;
	g_log_level = level;
	if (log_filename == NULL) {
		g_log_file = stdout;
		return 0;
	}

	new_log_file = fopen(log_filename, "a");
	if (new_log_file == NULL) {
		return -1;
	}
	g_log_file = new_log_file;
	return 0;
}

void log_printf(log_level_t level, const char* format, ...) {
	va_list args;
	if (level < g_log_level) {
		return;
	}
	if (g_log_file == NULL) {
		return;
	}
	level_printf(level);
	va_start(args, format);
	vfprintf(g_log_file, format, args);
	fflush(g_log_file);
	va_end(args);
	return;
}

void log_printf_addr(struct sockaddr *addr) {
	/* Make sure there's enough room for IPv6 addresses */
	char str[INET6_ADDRSTRLEN];
	unsigned long ip_addr;
	struct in6_addr ip6_addr;
	int port;
	if (addr->sa_family == AF_INET) {
		ip_addr = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
		inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
		port = (int)ntohs(((struct sockaddr_in*)addr)->sin_port);
	}
	else {
		ip6_addr = ((struct sockaddr_in6*)addr)->sin6_addr;
		inet_ntop(AF_INET6, &ip6_addr, str, INET6_ADDRSTRLEN);
		port = (int)ntohs(((struct sockaddr_in6*)addr)->sin6_port);
	}
	log_printf(LOG_INFO, "Address: %s:%d\n", str, port);
	return;
}

void log_close(void) {
	if (g_log_file != stdout) {
		fclose(g_log_file);
	}
	g_log_file = NULL;
	return;
}

void level_printf(log_level_t level) {
	char level_str[32];
	switch(level) {
		case LOG_DEBUG:
			strcpy(level_str, "DEBUG:   ");
			break;
		case LOG_INFO:
			strcpy(level_str, "INFO:    ");
			break;
		case LOG_WARNING:
			strcpy(level_str, "WARNING: ");
			break;
		case LOG_ERROR:
			strcpy(level_str, "ERROR:   ");
			break;
	}
	fprintf(g_log_file, "%s", level_str);
	return;
}


int timeval_subtract(struct timeval* result, struct timeval* x, struct timeval* y) {
	struct timeval y_cpy = *y;
	/* Perform the carry for the later subtraction by updating y_cpy. */
	if (x->tv_usec < y_cpy.tv_usec) {
	int nsec = (y_cpy.tv_usec - x->tv_usec) / 1000000 + 1;
		y_cpy.tv_usec -= 1000000 * nsec;
		y_cpy.tv_sec += nsec;
	}
	if (x->tv_usec - y_cpy.tv_usec > 1000000) {
		int nsec = (x->tv_usec - y_cpy.tv_usec) / 1000000;
		y_cpy.tv_usec += 1000000 * nsec;
		y_cpy.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y_cpy.tv_sec;
	result->tv_usec = x->tv_usec - y_cpy.tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y_cpy.tv_sec;
}
#endif

