#include <stdlib.h>
#include <stdio.h>

#include "hashmap.h"

typedef struct hnode {
	struct hnode* next;
	unsigned long key;
	void* value;
} hnode_t;


static int hash(hmap_t* map, unsigned long key);

int hash(hmap_t* map, unsigned long key) {
	return key % map->num_buckets;
}

hmap_t* hashmap_create(int num_buckets) {
	hmap_t* map = (hmap_t*)malloc(sizeof(hmap_t));
	if (map == NULL) {
		return NULL;
	}
	map->buckets = (hnode_t**)calloc(num_buckets, sizeof(hnode_t*));
	if (map->buckets == NULL) {
		free(map);
		return NULL;
	}
	map->num_buckets = num_buckets;
	return map;
}

void hashmap_free(hmap_t* map) {
	hnode_t* cur = NULL;
	hnode_t* tmp = NULL;
	int i;
	if (map == NULL) {
		return;
	}
	for (i = 0; i < map->num_buckets; i++) {
		cur = map->buckets[i];
		while (cur != NULL) {
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
	free(map->buckets);
	free(map);
}

int hashmap_add(hmap_t* map, unsigned long key, void* value) {
	int index;
	hnode_t* cur;
	hnode_t* new_node = (hnode_t*)malloc(sizeof(hnode_t));
	new_node->key = key;
	new_node->value = value;
	new_node->next = NULL;
	
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		map->buckets[index] = new_node;
		map->item_count++;
		return 0;
	}
	while (cur->next != NULL) {
		if (cur->key == key) {
			/* Duplicate entry */
			return 1;
		}
		cur = cur->next;
	}
	cur->next = new_node;
	map->item_count++;
	return 0;
}

int hashmap_del(hmap_t* map, unsigned long key) {
	int index;
	hnode_t* cur;
	hnode_t* tmp;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return 1;
	}
	if (cur->key == key) {
		map->buckets[index] = cur->next;
		free(cur);
		map->item_count--;
		return 0;
	}
	while (cur->next != NULL) {
		if (cur->next->key == key) {
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

void* hashmap_get(hmap_t* map, unsigned long key) {
	int index;
	hnode_t* cur;
	index = hash(map, key);
	cur = map->buckets[index];
	if (cur == NULL) {
		/* Not found */
		return NULL;
	}
	if (cur->key == key) {
		return cur->value;
	}
	while (cur->next != NULL) {
		if (cur->next->key == key) {
			return cur->next->value;
		}
	}
	return NULL;
}

void hashmap_print(hmap_t* map) {
	int i;
	hnode_t* cur;
	printf("Hash map contents:\n");
	for (i = 0; i < map->num_buckets; i++) {
		printf("\tBucket %d:\n", i);
		cur = map->buckets[i];
		while (cur) {
			printf("\t\tNode [key = %lu, value=%p]\n",
				cur->key, cur->value);
			cur = cur->next;
		}
	}
	return;
}
