#ifndef HELPER_H
#define HELPER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../../hashmap.h"
#include <dlfcn.h>
#include <ctype.h>
#include <unistd.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "unix_helper.h"
#include "../../in_tls.h" 
#include "../../ipc.h"

/*
a struct with type tls_sock_data_t contain all information of a socket
*/
typedef struct tls_sock_data { 
    unsigned long key;
    struct socket* unix_sock;
    struct sockaddr* ext_addr; /* external address */
    int ext_addrlen; /* external address length */
    struct sockaddr int_addr; /* internal address */
    int int_addrlen; /* internal address length */
    struct sockaddr rem_addr; /* remote address */
    int rem_addrlen; //remote address length
    struct sockaddr* peer_addr;
    int peer_addrlen;
    char *hostname; //the host name for example: www.google.com
    int is_bound; //value of if a socket is bind with an address or not
    int async_connect; //to be consider...
    int interrupted; //to be consider...
    int response; //response number
    char* rdata; /* returned data from asynchronous callback */
    unsigned int rdata_len; /* length of data returned from async callback to be consider... */
    unsigned long daemon_id; /* userspace daemon to which the socket is assigned */
} tls_sock_data_t;

unsigned long concatenate(unsigned long x, int y);
int is_valid_host_string(char* str, int len);
char* get_addr_string(struct sockaddr *addr);
void put_tls_sock_data(hmap_t* sock_map, unsigned long key, tls_sock_data_t* sock_data);
tls_sock_data_t* get_tls_sock_data(hmap_t* sock_map, unsigned long key);

#endif