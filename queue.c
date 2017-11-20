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
#include <stdio.h>

#include "queue.h"

typedef struct node {
	void* value;
	struct node* next;
} node_t;

queue_t* queue_create(void) {
	queue_t* q;
	q = (queue_t*)malloc(sizeof(queue_t));
	if (q == NULL) {
		return NULL;
	}
	q->item_count = 0;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

void queue_free(queue_t* q) {
	node_t* cur;
	node_t* tmp;
	if (q == NULL) {
		return;
	}
	cur = q->head;
	while (cur != NULL) {
		tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	free(q);
	return;
}

int queue_enc(queue_t* q, void* value) {
	node_t* new_node;
	new_node = (node_t*)calloc(1, sizeof(node_t));
	if (new_node == NULL) {
		return 1;
	}
	new_node->value = value;
	
	if (q->head == NULL) {
		q->head = new_node;
		q->tail = new_node;
		q->item_count++;
		return 0;
	}

	q->tail->next = new_node;
	q->tail = new_node;
	q->item_count++;
	return 0;
}

void* queue_deq(queue_t* q) {
	node_t* node;
	void* value;
	if (q->head == NULL) {
		return NULL;
	}
	node = q->head;
	value = node->value;
	q->head = node->next;

	if (q->head == NULL) {
		q->tail = NULL;
	}

	free(node);
	q->item_count--;
	return value;
}

void queue_print(queue_t* q) {
	node_t* cur;
	printf("Queue contains:\n");
	cur = q->head;
	while (cur != NULL) {
		printf("\tNode with value %p\n", cur->value);
		cur = cur->next;
	}
	return;
}

