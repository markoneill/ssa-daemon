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
#include <string.h>
#include "hashmap_str.h"
#define STR_MATCH(s, n) strcmp(s, n) == 0

typedef struct hsnode {
	struct hsnode* next;
	char* key;
	void* value;
} hsnode_t;

static int hash(hsmap_t* map, char* key);

int hash(hsmap_t* map, char* key)
{
	int i;
	int hash_val = 0;
	
	for (int i = 0; i < strlen(key); ++i)
	{
		hash_val += key[i];
	}

	return hash_val % map->num_buckets;
}


hsmap_t* str_hashmap_create(int num_buckets) {
	hsmap_t* map = (hsmap_t*)malloc(sizeof(hsmap_t));
	if (map == NULL) {
		return NULL;
	}
	map->buckets = (hsnode_t**)calloc(num_buckets, sizeof(hsnode_t*));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}
	map->num_buckets = num_buckets;
	return map;
}

void str_hashmap_deep_free(hsmap_t* map, void (*free_func)(void*)) {
	hsnode_t* cur = NULL;
	hsnode_t* tmp = NULL;
	int i;
	if (map == NULL) {
		return;
	}
	for (i = 0; i < map->num_buckets; i++) {
		cur = map->buckets[i];
		while (cur != NULL) {
			tmp = cur->next;
			if (free_func != NULL) {
				free_func(cur->value);
			}
			free(cur);
			cur = tmp;
		}
	}
	free(map->buckets);
	free(map);
	return;
}

void str_hashmap_free(hsmap_t* map) {
	str_hashmap_deep_free(map, NULL);
	return;
}

int str_hashmap_add(hsmap_t* map, char* key, void* value) {
	int index;
	hsnode_t* cur;
	hsnode_t* next;
	hsnode_t* new_node = (hsnode_t*)malloc(sizeof(hsnode_t));
	new_node->key = key;
	new_node->value = value;
	new_node->next = NULL;

	if (key == NULL) {
		return 1;
	}
	
	index = hash(map, key);
	cur = map->buckets[index];
	next = cur;
	if (cur == NULL) {
		map->buckets[index] = new_node;
		map->item_count++;
		return 0;
	}

	do {
		cur = next;
		if(STR_MATCH(cur->key,key)) {
			/* Duplicate entry */

			return 1;
		}
		next = cur->next;
	} while (next != NULL);

	cur->next = new_node;
	map->item_count++;
	return 0;
}

int str_hashmap_del(hsmap_t* map, char* key) {
	int index;
	hsnode_t* cur;
	hsnode_t* tmp;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 1;
	}
	if (STR_MATCH(cur->key,key)) {
		map->buckets[index] = cur->next;
		free(cur);
		map->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
		if (STR_MATCH(cur->key,key)) {
			tmp = cur->next;
			cur->next = cur->next->next;
			free(tmp);
			map->item_count--;
			return 0;
		}
		cur = cur->next;
	}
	/* Not found */
	return 1;
}

void* str_hashmap_get(hsmap_t* map, char* key) {
	int index;
	hsnode_t* cur;

	if (key == NULL)
	{
		return NULL;
	}

	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return NULL;
	}
	if (STR_MATCH(cur->key,key)) {
		return cur->value;
	}
	while (cur->next != NULL) {
		if (STR_MATCH(cur->next->key,key)) {
			return cur->next->value;
		}
		cur = cur->next;
	}
	return NULL;
}


void str_hashmap_print(hsmap_t* map) {
	int i;
	hsnode_t* cur;
	printf("Hash map contents:\n");
	for (i = 0; i < map->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = map->buckets[i];
		while (cur) {
			printf("\t\tNode [key = \"%s\", value=%p]\n",
				cur->key, cur->value);
			cur = cur->next;
		}
	}
	return;
}
