#define _GNU_SOURCE  

#include <stdlib.h>
#include <stdio.h>
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
#include "message_sender.h"
#include "../../in_tls.h" 
#include "../../hashmap.h"
#include "../../ipc.h"

#define HASHMAP_NUM_BUCKETS 100
#define MAX_HOST_LEN        255

hmap_t* sock_map; //the map that contain all the sock infomation
pthread_mutex_t id_mutex;

int socket(int domain, int type, int protocol){
  sock_map = hashmap_create(HASHMAP_NUM_BUCKETS);
  if(protocol == IPPROTO_TLS){
    int tcp_fd;
    int unix_fd;
    unsigned long daemon_id = 0;
    unsigned long process_id = 0;
    tls_sock_data_t* sock_data; //define a new struct to store the sock data

    if((sock_data = malloc(sizeof(tls_sock_data_t))) == NULL){
        perror("fail in sock data malloc");
        return -1;
    }
    // create a TCP socket
    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    tcp_fd = socket_orig(AF_INET, SOCK_STREAM, 0);
    if(tcp_fd == -1){
    printf("Error opening socket\n");
    return -1;
    }

    // specifying internal address (aka local address), but not bind with the socket yet
    ((struct sockaddr_in*)&sock_data->int_addr)->sin_family = AF_INET;
    ((struct sockaddr_in*)&sock_data->int_addr)->sin_port = 0;
    ((struct sockaddr_in*)&sock_data->int_addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock_data->is_bound = 0;
    //set tcp_fd number to be the key
    sock_data->key = (unsigned long)tcp_fd;
    printf("%s%s\n", "internal address: ", get_addr_string(&(sock_data->int_addr))); 
    //generating daemon id, damemon id is concatenation of preocess id and fd number
    pthread_mutex_lock(&id_mutex);
    process_id = getpid();
    daemon_id = concatenate(process_id, tcp_fd);
    pthread_mutex_unlock(&id_mutex);
    //put sock data in sock map
    sock_data->daemon_id = daemon_id;
    put_tls_sock_data(sock_map, sock_data->key, sock_data);
    //create unix domain socket and send all the information
    int ret = send_socket_message(daemon_id);
    return tcp_fd;
  }
  else{
    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    return socket_orig(domain, type, protocol);
  }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(hashmap_get(sock_map, sockfd) != NULL){
    printf("%s\n", "enter in connect function");
    int bind_result;
    tls_sock_data_t* sock_data;
    sock_data = get_tls_sock_data(sock_map, sockfd);

    struct sockaddr remote_address = *addr;
    sock_data->rem_addr = remote_address;

    //if the socket is not bound with an address, bind it with internal address(aka lcoal address)
    if(sock_data->is_bound == 0){
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, &(sock_data->int_addr), sizeof(sock_data->int_addr));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(sock_data->int_addr);
        getsockname(sockfd, &(sock_data->int_addr), &size);
        sock_data->is_bound = 1;
    }

    int ret = send_connect_message(sockfd, sock_data->daemon_id, (struct sockaddr*)&sock_data->int_addr, &remote_address);

    return 0;
  }
  else{
    orig_connect_type connect_orig;
    connect_orig = (orig_connect_type)dlsym(RTLD_NEXT,"connect");
    int connect_id = connect_orig(sockfd, addr, addrlen);
    if(connect_id == -1){
          printf("Error connecting socket\n");
          return -1;
      }
    return connect_id;
  }
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen){
    if(hashmap_get(sock_map, sockfd) != NULL){
    int len;
    int ret;
    char resolved_path[PATH_MAX];
    char* optval_temp;
    tls_sock_data_t* sock_data;
    sock_data = get_tls_sock_data(sock_map, sockfd);

    if (optval == NULL) {
        return -EINVAL; 
    }
    if (optlen == 0) {
        return -EINVAL;
    }

    optval_temp = malloc(optlen);
    memcpy(optval_temp, optval, optlen);

    switch(optname){
        case TLS_REMOTE_HOSTNAME:
            if(optlen > MAX_HOST_LEN){
                ret = -EINVAL;
            }
            if (!is_valid_host_string(optval_temp, len)) {
                ret = -EINVAL;
            }
            ret = 0;
            break;
        case TLS_HOSTNAME:
            ret = 0;
            break;
        case TLS_TRUSTED_PEER_CERTIFICATES:
        case TLS_CERTIFICATE_CHAIN:
        case TLS_PRIVATE_KEY:
            /* We convert relative paths to absolute ones
             * here. We also skip things prefixed with '-'
             * because that denotes direct PEM encoding */
            if (optval_temp[0] != '-' && optval_temp[0] != '/') {
                if (realpath(optval_temp, resolved_path) == NULL) {
                    return -ENOMEM;
                }
            }
            free(optval_temp);
            optlen = strlen(resolved_path);
            optval_temp = malloc(optlen);
            strncpy(optval_temp, resolved_path, optlen);
            ret = 0;
            break;
        case TLS_ALPN:
        case TLS_SESSION_TTL:
        case TLS_DISABLE_CIPHER:
        case TLS_PEER_IDENTITY:
            ret = 0;
            break;
        case TLS_REQUEST_PEER_AUTH:
            ret = 0;
            break;
        case TLS_PEER_CERTIFICATE_CHAIN:
        case TLS_ID:
        default:
         ret = 0;
         break;
    }

    if(ret != 0){
        free(optval_temp);
        return ret;
    }
    
    ret = send_setsockopt_message(sock_data->daemon_id, level, optname, optval_temp);
    if(ret < 0){
        free(optval_temp);
        return -1;
    }

    //need to figure out this part ????????????????????
    if (level != IPPROTO_TLS) {
        orgi_setsockopt_type setsockopt_orgi;
        setsockopt_orgi = (orgi_setsockopt_type)dlsym(RTLD_NEXT,"setsockopt");
        return setsockopt_orgi(sockfd, level, optname, optval, optlen);
    }

    return 0;
    }
    else{
        orgi_setsockopt_type setsockopt_orgi;
        setsockopt_orgi = (orgi_setsockopt_type)dlsym(RTLD_NEXT,"setsockopt");
        return setsockopt_orgi(sockfd, level, optname, optval, optlen);
    } 
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen){
  if(hashmap_get(sock_map, sockfd) != NULL){
    int ret;
    char buff[8192];
    tls_sock_data_t* sock_data;
    sock_data = get_tls_sock_data(sock_map, sockfd);

    if(level != IPPROTO_TLS){
        orgi_getsockopt_type getsockopt_orgi;
        getsockopt_orgi = (orgi_getsockopt_type)dlsym(RTLD_NEXT,"getsockopt");
        return getsockopt_orgi(sockfd, level, optname, optval, optlen);
    }


    switch (optname) {
    case TLS_REMOTE_HOSTNAME: // just return the hostname
         //strncpy(optval, buff, *optlen);
         return 0;
    case TLS_HOSTNAME:
    case TLS_TRUSTED_PEER_CERTIFICATES:
    case TLS_CERTIFICATE_CHAIN:
    case TLS_PRIVATE_KEY:
    case TLS_ALPN:
    case TLS_SESSION_TTL:
    case TLS_DISABLE_CIPHER:
    case TLS_PEER_IDENTITY:
    case TLS_REQUEST_PEER_AUTH:
    case TLS_PEER_CERTIFICATE_CHAIN:
        
        ret = send_getsockopt_message(sock_data->daemon_id, level, optname, optval, optlen);
        if(ret < 0){
            return -1;
        }

    case TLS_ID:
        //return id;
    default:
        return -EOPNOTSUPP;
    }
   }
   else{
      printf("establishing normal getsockopt...\n");
      orgi_getsockopt_type getsockopt_orgi;
      getsockopt_orgi = (orgi_getsockopt_type)dlsym(RTLD_NEXT,"getsockopt");
      return getsockopt_orgi(sockfd, level, optname, optval, optlen);
   }
}

int close(int fd){
  if(hashmap_get(sock_map, fd) != NULL){
    tls_sock_data_t* sock_data;
    sock_data = get_tls_sock_data(sock_map, fd);
    
    //the fd that passed in can be the fd returned by socket() function can also be fd returned by accept() function
    int ret = send_close_message(sock_data->daemon_id);
    if(ret < 0){
        return -1;
    }
    //close tcp socket
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    ret = close_orgi(fd); 
    unlink(SOCKET_PRELOAD_FILE);
    return ret;
  }
  else{
    printf("establishing normal close...\n");
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    return close_orgi(fd);
  }
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    if(hashmap_get(sock_map, sockfd) != NULL){
    int process_id;
    unsigned long new_id;
    int new_tcp_fd;

    tls_sock_data_t* sock_data; 
    if((sock_data = malloc(sizeof(tls_sock_data_t))) == NULL){
        perror("fail in sock data malloc");
        return -1;
    }

    orgi_accept_type accept_orgi;
    accept_orgi = (orgi_accept_type)dlsym(RTLD_NEXT,"accept");

    //accept will create a new tcp socket
    new_tcp_fd = accept_orgi(sockfd, addr, addrlen);
    if(new_tcp_fd == -1){
        perror("error in accept");
    }

    //get the peer address associated with new tcp socket
    struct sockaddr_in peer_address;
    int peer_len;
    peer_len = sizeof(peer_address);
    if (getpeername(new_tcp_fd, &peer_address, &peer_len) == -1) {
        perror("getpeername() failed");
        return -1;
    }

    sock_data->peer_addr = (struct sockaddr*)&peer_address;
    sock_data->key = (unsigned long)new_tcp_fd;

    //create new id for the new socket
    process_id = getpid();
    new_id  = concatenate(process_id, new_tcp_fd);
    sock_data->daemon_id = new_id;
    put_tls_sock_data(sock_map, sock_data->key, sock_data);

    int ret = send_accept_message(new_id, peer_address);
    if(ret < 0){
        return -1;
    }
    
    return new_tcp_fd;
    }
    else{
        orgi_accept_type accept_orgi;
        accept_orgi = (orgi_accept_type)dlsym(RTLD_NEXT,"accept");
        return accept_orgi(sockfd, addr, addrlen);
    }
}

int listen(int sockfd, int backlog){
    if(hashmap_get(sock_map, sockfd) != NULL){
    tls_sock_data_t* sock_data;
    if((sock_data = malloc(sizeof(tls_sock_data_t))) == NULL){
        perror("fail in sock data malloc");
        return -1;
    }
    sock_data = get_tls_sock_data(sock_map, sockfd);

    if(sock_data->is_bound == 0){
        int bind_result;
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, (struct sockaddr*) &(sock_data->int_addr), sizeof(sock_data->int_addr));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(sock_data->int_addr);
        getsockname(sockfd, (struct sockaddr *) &(sock_data->int_addr), &size);
        sock_data->is_bound == 1;
    }
 
    int ret = send_listen_message(sock_data->daemon_id, (struct sockaddr*)&(sock_data->int_addr), sock_data->ext_addr);
    if(ret < 0){
        return -1;
    }

    orgi_listen_type listen_orgi;
    listen_orgi = (orgi_listen_type)dlsym(RTLD_NEXT,"listen");
    ret = listen_orgi(sockfd, backlog);
    if(ret < 0){
        perror("listen error");
        return -1;
    }

    return ret;
  }
  else{
    orgi_listen_type listen_orgi;
    listen_orgi = (orgi_listen_type)dlsym(RTLD_NEXT,"listen");
    return listen_orgi(sockfd, backlog);
  }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(hashmap_get(sock_map, sockfd) != NULL){
        int bind_result;
        tls_sock_data_t* sock_data; //define a new struct to store the sock data
        if((sock_data = malloc(sizeof(tls_sock_data_t))) == NULL){
            perror("malloc sock_data failed in bind");
            return -1;
        }
        sock_data = get_tls_sock_data(sock_map, sockfd);

        // bind on the local adress that was created in the socket()
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, (struct sockaddr*) &(sock_data->int_addr), sizeof(sock_data->int_addr));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(sock_data->int_addr);
        getsockname(sockfd, (struct sockaddr *) &(sock_data->int_addr), &size);

        if(addr->sa_family == AF_INET){
            sock_data->ext_addr = (struct sockaddr *) addr;
        }

        sock_data->is_bound = 1;

        int ret = send_bind_message(sock_data->daemon_id, (struct sockaddr*)&(sock_data->int_addr), sock_data->ext_addr);
        if(ret < 0){
            return -1;
        }
        return 0;
    }
    else{
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        return bind_orgi(sockfd, addr, addrlen);
    }
}