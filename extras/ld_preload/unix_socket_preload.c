#define _GNU_SOURCE  

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <linux/limits.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../../in_tls.h" 
#include "../../hashmap.h"
#include "../../ipc.h"

typedef int (*orig_socket_type)(int domain, int type, int protocol);
typedef int (*orig_connect_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef int (*orgi_setsockopt_type)(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen);
typedef int (*orgi_getsockopt_type)(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
typedef int (*orgi_close_type)(int fd);
typedef int (*orgi_listen_type)(int sockfd, int backlog); 
typedef int (*orgi_accept_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*orgi_bind_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#define SNAME "/mysem"
#define HASHMAP_NUM_BUCKETS 100

int global_id = 0;
int global_fd = 0;
int new_accept_id = 0;
int global_tcp_fd = 0;
int is_bind = 0;
hmap_t* sock_map;
struct sockaddr_in local_address;
struct sockaddr_in* addr_external;

unsigned long concatenate(unsigned long x, int y) { //combine two int
    unsigned long pow = 10;
    while(y >= pow){
      pow *= 10;
    }
    return x * pow + y;
}

char* get_addr_string(struct sockaddr *addr) {
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

    char portString[256];
    char semicolon[2];
    strcpy(semicolon, ":");
    sprintf(portString, "%ld", port);
    strcat(str, semicolon);
    strcat(str, portString);

    printf("the address is: %s\n", str);

    char *result = malloc(sizeof(str));
    memcpy(result, str, sizeof(str));

    return result;
}

int createUnixSocket(){
    // crete the server file here as well
    int fd;
    int ret;
    struct sockaddr_un addr;

    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    if ((fd = socket_orig(PF_UNIX, SOCK_DGRAM, 0)) < 0) { // create a unix domian socket
        perror("error in create socket.");
        return -1;
    }
    global_fd = fd;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_PRELOAD_FILE);
    ret = unlink(SOCKET_PRELOAD_FILE);
    orgi_bind_type bind_orgi;
    bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
    ret = bind_orgi(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind failed");
        return -1;
    }

    // make the connection with the server side
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SERVER_SOCK_FILE);

    orig_connect_type connect_orig;
    connect_orig = (orig_connect_type)dlsym(RTLD_NEXT,"connect");
    ret = connect_orig(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        perror("connect failed in create unix socket");
        return -1;
    }
    return fd;
}

int socket(int domain, int type, int protocol){
  int port_id = 8443;
  sock_map = hashmap_create(HASHMAP_NUM_BUCKETS);
  if(protocol == IPPROTO_TLS){
    int fd;
    int len;
    int ret;
    char buff[8192];
    unsigned long id;
    unsigned long process_id = 0;

    // TCP socket
      int tcp_fd;
      orig_socket_type socket_orig;
      socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
      tcp_fd = socket_orig(AF_INET, SOCK_STREAM, 0);
      if(tcp_fd == -1){
        printf("Error opening socket\n");
        return -1;
    }
    
    // create a local address
    local_address.sin_family = AF_INET;
    local_address.sin_port = 0;
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    get_addr_string((struct sockaddr*)&local_address);

    process_id = getpid();
    id  = concatenate(process_id, tcp_fd);
    global_id = id;
    global_tcp_fd = tcp_fd;

    hashmap_add(sock_map, id, (void*)(long)tcp_fd); // key and value
 
    fd = createUnixSocket();
   
    // send ssa socket notify
    strcpy(buff, "1 ssa socket notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send failed in socket");
        return -1;
    }

    // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "1id");
    sprintf(idString, "%ld", id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed socket");
        return -1;
    }

    char *comm_ptr;
    char *symlinkpath = "/proc/self/exe";
    char actualpath [PATH_MAX+1];
    strcpy(resultMark, "1pa");
    comm_ptr = realpath(symlinkpath, actualpath);
    comm_ptr = strcat(resultMark, comm_ptr);
    strcpy(buff, comm_ptr);

    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send comm_ptr failed in socket");
        return -1;
    }

    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received message for socket: %s\n", buff);
    
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);

    return tcp_fd;
  }
  else{
    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    return socket_orig(domain, type, protocol);
  }
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen){
    if(optname == 85 || optname == 86 || optname == 87 || optname == 88 || optname == 89 ||
       optname == 90 || optname == 91 || optname == 92 || optname == 93 || optname == 94 || optname == 95){
    int fd;
    int len;
    int ret;
    char buff[8192];
    unsigned long id;
    // send setsockpot notify

    fd = createUnixSocket();
    strcpy(buff, "2 ssa setsockpot notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in setsockopt");
        return -1;
    }

    // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "2id");
    sprintf(idString, "%ld", global_id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send level
    char levelString[256];
    strcpy(resultMark, "2le");
    sprintf(levelString, "%ld", level);
    strcat(resultMark, levelString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send level failed");
        return -1;
    }

    // send option name
    char optnameString[256];
    strcpy(resultMark, "2on");
    sprintf(optnameString, "%ld", optname);
    strcat(resultMark, optnameString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send level failed");
        return -1;
    }

    // send optval
    strcpy(resultMark, "2ov");
    strcat(resultMark, optval);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send optval failed");
        return -1;
    }

    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received messgae for setsockopt: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);

    return 0;
    }
    else{
        orgi_setsockopt_type setsockopt_orgi;
        setsockopt_orgi = (orgi_setsockopt_type)dlsym(RTLD_NEXT,"setsockopt");
        return setsockopt_orgi(sockfd, level, optname, optval, optlen);
    }
}

int make_connection(int sockfd){
    struct sockaddr_in tlswrap_address;
    tlswrap_address.sin_family = AF_INET;
    tlswrap_address.sin_port = htons(8443);
    inet_aton("127.0.0.1", &tlswrap_address.sin_addr);
    orig_connect_type connect_orig;
    connect_orig = (orig_connect_type)dlsym(RTLD_NEXT,"connect");
    int connect_id = connect_orig(sockfd, (struct sockaddr*)&tlswrap_address, sizeof(tlswrap_address));
    if(connect_id == -1){    
          printf("Error connecting socket\n");
         return -1;
     }
    return 0;
}

// need to look at the tls_inet what is the reroute address

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(hashmap_get(sock_map, global_id) != NULL){
    int bind_result;
    struct nl_msg* msg;
    int fd;
    int len;
    int ret;
    char buff[8192];
    unsigned long id;
    void* msg_head;
    int blocking = 1;

    if(is_bind == 0){
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, (struct sockaddr*) &local_address, sizeof(local_address));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(local_address);
        getsockname(sockfd, (struct sockaddr *) &local_address, &size);
    }
    
    // ------------------send message ------------------
    fd = createUnixSocket();
    // send connection notify
    strcpy(buff, "3 ssa connection notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }

    // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "3id");
    sprintf(idString, "%ld", global_id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send local address
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string((struct sockaddr*)&local_address));
    strcpy(resultMark, "3la");
    strcat(resultMark, localAddressString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }

    // send remote address
    char addrString[256];
    strcpy(addrString, get_addr_string((struct sockaddr*) addr));
    strcpy(resultMark, "3ra");
    strcat(resultMark, addrString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send remote address failed");
        return -1;
    }

    // send blocking
    char blockingString[256];
    strcpy(resultMark, "3bn");
    sprintf(blockingString, "%ld", blocking);
    strcat(resultMark, blockingString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send blocking failed");
        return -1;
    }
    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received message for connection: %s\n", buff);

    //semaphore
    int unlink = sem_unlink(SNAME);
    sem_t *sem_connect = sem_open(SNAME, O_CREAT, 0644, 0);
    int sem_value = sem_wait(sem_connect);
    int connection_check = make_connection(sockfd); 
    if(connection_check == -1){
      return -1;
    }
    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
     }
    printf("receive message for connection: %s\n", buff);
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);

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


// need to look at the getsockopt in the tls_common the different iotname have different things need to do
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen){
  if(optname == SO_REMOTE_HOSTNAME || optname == SO_HOSTNAME || optname == SO_TRUSTED_PEER_CERTIFICATES || optname == SO_CERTIFICATE_CHAIN
     || optname == SO_PRIVATE_KEY || optname == SO_ALPN || optname == SO_SESSION_TTL || optname == SO_DISABLE_CIPHER || optname == SO_PEER_IDENTITY
     || optname == SO_PEER_CERTIFICATE || optname == SO_ID){
    int fd;
    int len;
    int ret;
    char buff[8192];
    unsigned long id;

    fd = createUnixSocket();
    // send ssa socket notify
    strcpy(buff, "4 ssa getsockopt notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send failed in getsockopt");
        return -1;
    }

     // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "4id");
    sprintf(idString, "%ld", global_id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send level
    char levelString[256];
    strcpy(resultMark, "4le");
    sprintf(levelString, "%ld", level);
    strcat(resultMark, levelString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send level failed");
        return -1;
    }

    // send option name
    char optnameString[256];
    strcpy(resultMark, "4on");
    sprintf(optnameString, "%ld", optname);
    strcat(resultMark, optnameString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send level failed");
        return -1;
    }

    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    strcpy(optval, buff);
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);
   }
   else{
      printf("establishing normal getsockopt...\n");
      orgi_getsockopt_type getsockopt_orgi;
      getsockopt_orgi = (orgi_getsockopt_type)dlsym(RTLD_NEXT,"getsockopt");
      return getsockopt_orgi(sockfd, level, optname, optval, optlen);
   }
}

int close(int fd){
  if(hashmap_get(sock_map, global_id) != NULL){
    int ret;
    int len;
    int unix_fd;
    unsigned long id;
    char buff[8192];

    unix_fd = createUnixSocket();
    strcpy(buff, "5 ssa close notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in close");
        return -1;
    }
    // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "5id");
    if(fd == (new_accept_id % 10)){
        sprintf(idString, "%ld", new_accept_id);
    }
    else{
        sprintf(idString, "%ld", global_id);
    }
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("the messgae received in close: %s\n", buff);

    printf("the closed fd number: %d\n", fd);

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
    if(hashmap_get(sock_map, global_id) != NULL){
    int fd;
    int len;
    int ret;
    int process_id;
    int new_id;
    int new_tcp_fd;
    char buff[8192];
    unsigned long id;

    orgi_accept_type accept_orgi;
    accept_orgi = (orgi_accept_type)dlsym(RTLD_NEXT,"accept");

    printf("here in accept with sockfd: %d\n", sockfd);
    new_tcp_fd = accept_orgi(sockfd, addr, addrlen);
    if(new_tcp_fd == -1){
        perror("error in accept");
    }
    printf("new_tcp_fd number: %d\n", new_tcp_fd);

    struct sockaddr_in peer_address;
    int peer_len;
    peer_len = sizeof(peer_address);
          /* Ask getpeername to fill in peer's socket address.  */
    if (getpeername(new_tcp_fd, &peer_address, &peer_len) == -1) {
        perror("getpeername() failed");
        return -1;
    }
    printf("Peer's IP address is: %s\n", inet_ntoa(peer_address.sin_addr));
    printf("Peer's port is: %d\n", (int) ntohs(peer_address.sin_port));

    struct sockaddr_in current_address;
    int current_len;
    current_len = sizeof(current_address);
    if (getsockname(new_tcp_fd, &current_address, &current_len) == -1) {
    perror("getsockname");
    return -1;
    }
    get_addr_string((struct sockaddr*)&current_address);

    //need to find out the port that it is connected to(the one get listened on) and send back the address with the port number that it is connected to. 

    fd = createUnixSocket();
    strcpy(buff, "6 ssa listen notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }

    //create new id for the new socket
    process_id = getpid();
    new_id  = concatenate(process_id, new_tcp_fd);
    new_accept_id = new_id;

    // send the id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "6id");
    sprintf(idString, "%ld", new_id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send new local address
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string((struct sockaddr*)&peer_address));
    strcpy(resultMark, "6la");
    strcat(resultMark, localAddressString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }

    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    printf("the messgae received in accept: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);

    printf("the new fd number: %d\n", new_tcp_fd);

    return new_tcp_fd;
    }
    else{
        orgi_accept_type accept_orgi;
        accept_orgi = (orgi_accept_type)dlsym(RTLD_NEXT,"accept");
        return accept_orgi(sockfd, addr, addrlen);
    }
}

int listen(int sockfd, int backlog){
    if(hashmap_get(sock_map, global_id) != NULL){
    int fd;
    int len;
    int ret;
    char buff[8192];
    unsigned long id;
    struct sockaddr* addr;

    if(is_bind == 0){
        int bind_result;
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, (struct sockaddr*) &local_address, sizeof(local_address));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(local_address);
        getsockname(sockfd, (struct sockaddr *) &local_address, &size);
    }

    fd = createUnixSocket();
    strcpy(buff, "7 ssa listen notify");
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }

    // send id numeber
    char idString[256];
    char resultMark[256];
    strcpy(resultMark, "7id");
    sprintf(idString, "%ld", global_id);
    strcat(resultMark, idString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send local address
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string((struct sockaddr*)&local_address));
    strcpy(resultMark, "7la");
    strcat(resultMark, localAddressString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }

    // send external address
    char addrString[256];
    strcpy(addrString, get_addr_string((struct sockaddr*) addr_external));
    strcpy(resultMark, "7ea");
    strcat(resultMark, addrString);
    strcpy(buff, resultMark);
    ret = send(fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send remote address failed");
        return -1;
    }
    
    if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    printf("the messgae received in listen: %s\n", buff);

    orgi_listen_type listen_orgi;
    listen_orgi = (orgi_listen_type)dlsym(RTLD_NEXT,"listen");
    ret = listen_orgi(sockfd, backlog);
    if(ret < 0){
        perror("listen error");
        return -1;
    }

    struct sockaddr_in current_address;
    int current_len;
    current_len = sizeof(current_address);
    if (getsockname(sockfd, &current_address, &current_len) == -1) {
    perror("getsockname");
    return -1;
    }
    printf("Current IP address is in listen: %s\n", inet_ntoa(current_address.sin_addr));
    printf("Current port is in listen: %d\n", (int) ntohs(current_address.sin_port));

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(fd);

  }
  else{
    orgi_listen_type listen_orgi;
    listen_orgi = (orgi_listen_type)dlsym(RTLD_NEXT,"listen");
    return listen_orgi(sockfd, backlog);
  }
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(hashmap_get(sock_map, global_id) != NULL){
        int bind_result;
        int fd;
        int ret;
        int len;
        char buff[8192];
        is_bind = 1;

        // bind on the local adress that was created in the socket preload
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        bind_result = bind_orgi(sockfd, (struct sockaddr*) &local_address, sizeof(local_address));
        if (bind_result == -1) {
         printf("Failed in bind\n");
         return -1;
        }
        socklen_t size = sizeof(local_address);
        getsockname(sockfd, (struct sockaddr *) &local_address, &size);

        if(addr->sa_family == AF_INET){
            addr_external = (struct sockaddr_in*) addr;
        }

        //after binding send the message
        fd = createUnixSocket();
        strcpy(buff, "8 ssa close notify");
        ret = send(fd, buff, strlen(buff)+1, 0);
        if (ret == -1) {
            perror("send failed in close");
            return -1;
        }

        // send id numeber
        char idString[256];
        char resultMark[256];
        strcpy(resultMark, "8id");
        sprintf(idString, "%ld", global_id);
        strcat(resultMark, idString);
        strcpy(buff, resultMark);
        ret = send(fd, buff, strlen(buff)+1, 0);
        if (ret == -1) { // send can be used when a socket is in a connected state
            perror("send id failed in setsockopt");
            return -1;
        }

        // send local address
        char localAddressString[256];
        strcpy(localAddressString, get_addr_string((struct sockaddr*)&local_address));
        strcpy(resultMark, "8la");
        strcat(resultMark, localAddressString);
        strcpy(buff, resultMark);
        ret = send(fd, buff, strlen(buff)+1, 0);
        if (ret == -1) {
            perror("send local address failed");
            return -1;
        }

        // send external address
        char addrString[256];
        strcpy(addrString, get_addr_string((struct sockaddr*) addr_external));
        strcpy(resultMark, "8ea");
        strcat(resultMark, addrString);
        strcpy(buff, resultMark);
        ret = send(fd, buff, strlen(buff)+1, 0);
        if (ret == -1) {
            perror("send external address failed");
            return -1;
        }

        if ((len = recv(fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
        }

        printf("the messgae received in bind: %s\n", buff);

        orgi_close_type close_orgi;
        close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
        close_orgi(fd);
    }
    else{
        orgi_bind_type bind_orgi;
        bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
        return bind_orgi(sockfd, addr, addrlen);
    }
}

//gcc -shared -fPIC -ldl -lnl-3 -lnl-genl-3 -lpthread -lrt -o unix_socket_preload.so -I/usr/include/libnl3 unix_socket_preload.c ../../hashmap.c