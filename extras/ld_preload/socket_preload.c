#define _GNU_SOURCE

#include <dlfcn.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>   
#include <sys/stat.h> 
#include "../../in_tls.h" 
#include "../../hashmap.h"

enum {
        SSA_NL_A_UNSPEC,
  SSA_NL_A_ID,
  SSA_NL_A_BLOCKING,
  SSA_NL_A_COMM,
  SSA_NL_A_SOCKADDR_INTERNAL,
  SSA_NL_A_SOCKADDR_EXTERNAL,
  SSA_NL_A_SOCKADDR_REMOTE,
  SSA_NL_A_OPTLEVEL,
  SSA_NL_A_OPTNAME,
  SSA_NL_A_OPTVAL,
  SSA_NL_A_RETURN,
        SSA_NL_A_PAD,
        __SSA_NL_A_MAX,
};


#define SNAME "/mysem"
#define SSA_NL_A_MAX (__SSA_NL_A_MAX - 1)
#define HASHMAP_NUM_BUCKETS 100

enum {
        SSA_NL_C_UNSPEC,
        SSA_NL_C_SOCKET_NOTIFY,
  SSA_NL_C_SETSOCKOPT_NOTIFY,
  SSA_NL_C_GETSOCKOPT_NOTIFY,
        SSA_NL_C_BIND_NOTIFY,
        SSA_NL_C_CONNECT_NOTIFY,
        SSA_NL_C_LISTEN_NOTIFY,
  SSA_NL_C_ACCEPT_NOTIFY,
  SSA_NL_C_CLOSE_NOTIFY,
  SSA_NL_C_RETURN,
  SSA_NL_C_DATA_RETURN,
  SSA_NL_C_HANDSHAKE_RETURN,
        __SSA_NL_C_MAX,
};

#define SSA_NL_C_MAX (__SSA_NL_C_MAX - 1)

enum ssa_nl_groups {
        SSA_NL_NOTIFY,
};

static struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
        [SSA_NL_A_UNSPEC] = { .type = NLA_UNSPEC },
  [SSA_NL_A_ID] = { .type = NLA_UNSPEC },
  [SSA_NL_A_BLOCKING] = { .type = NLA_UNSPEC },
  [SSA_NL_A_COMM] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_INTERNAL] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_EXTERNAL] = { .type = NLA_UNSPEC },
  [SSA_NL_A_SOCKADDR_REMOTE] = { .type = NLA_UNSPEC },
        [SSA_NL_A_OPTLEVEL] = { .type = NLA_UNSPEC },
        [SSA_NL_A_OPTNAME] = { .type = NLA_UNSPEC },
        [SSA_NL_A_OPTVAL] = { .type = NLA_UNSPEC },
  [SSA_NL_A_RETURN] = { .type = NLA_UNSPEC },
};

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

int global_id = 0;
struct nl_sock* netlink_sock;
struct sockaddr_in local_address_global;
int last_response;
int family;
int group;
char* global_data;
hmap_t* sock_map;

unsigned long concatenate(unsigned long x, int y) {
    unsigned long pow = 10;
    while(y >= pow){
      pow *= 10;
    }
    return x * pow + y;
}

int recv_response_cb(struct nl_msg *msg, void *arg) {
  struct nlmsghdr* nlh;
  struct genlmsghdr* gnlh;
  struct nlattr* attrs[SSA_NL_A_MAX + 1];
  uint64_t id;
  uint32_t result;
  // Get Message
  nlh = nlmsg_hdr(msg);
  gnlh = (struct genlmsghdr*)nlmsg_data(nlh);
  genlmsg_parse(nlh, 0, attrs, SSA_NL_A_MAX, ssa_nl_policy);
  switch (gnlh->cmd) {
    case SSA_NL_C_RETURN:
      printf("Received a response of ssa_nl_c_return\n");
      id = nla_get_u64(attrs[SSA_NL_A_ID]);
      result = nla_get_u32(attrs[SSA_NL_A_RETURN]);
      last_response = result;
      break;
    case SSA_NL_C_DATA_RETURN:
      printf("Received a response of ssa_nl_c_data_return\n");
      int data_length = nla_len(attrs[SSA_NL_A_OPTVAL]);
      char* data = nla_data(attrs[SSA_NL_A_OPTVAL]);
      global_data = data;
      break;
    case SSA_NL_C_HANDSHAKE_RETURN:
      printf("Received a response of ssa_nl_c_handshake_return\n");
      id = nla_get_u64(attrs[SSA_NL_A_ID]);
      result = nla_get_u32(attrs[SSA_NL_A_RETURN]);
      break;
    default:
      printf("Received unanticipated response\n");
      break;
  }
  return 0;
}

int recv_response(void) {
  if (nl_recvmsgs_default(netlink_sock) < 0) {
    printf("Failed to receieve message\n");
  }
  return last_response;
}

int netlink_connect(int process_id){
      netlink_sock = nl_socket_alloc();
      if (netlink_sock == NULL){
          printf("failed in alloc netlink socket\n");
          return -1;   
      }
      nl_socket_set_local_port(netlink_sock, process_id);
      nl_socket_disable_seq_check(netlink_sock);
      nl_socket_modify_cb(netlink_sock, NL_CB_VALID, NL_CB_CUSTOM, recv_response_cb, (void*)netlink_sock);
      if (genl_connect(netlink_sock) != 0) {
        printf("Failed to connect to Generic Netlink control\n");
        return -1;
      }
      if ((family = genl_ctrl_resolve(netlink_sock, "SSA")) < 0) {
        printf("Failed to resolve SSA family identifier\n");
        return -1;
      }
      if ((group = genl_ctrl_resolve_grp(netlink_sock, "SSA", "notify")) < 0) {
        printf("Failed to resolve group identifier\n");
        return -1;
      }
      if (nl_socket_add_membership(netlink_sock, group) < 0) {
        printf("Failed to add membership to group\n");
        return -1;
      }
      return 0;
}

int socket(int domain, int type, int protocol){
  int port_id = 8443;
  sock_map = hashmap_create(HASHMAP_NUM_BUCKETS);
  if(protocol == IPPROTO_TLS){

      unsigned long process_id = 0;
      int fd = 0;
      unsigned long id;
      char *symlinkpath = "/proc/self/exe";
      char actualpath [PATH_MAX+1];
      char *comm_ptr;
      struct nl_msg* msg;
      int ret;
      void* msg_head;
      process_id = getpid();
      comm_ptr = realpath(symlinkpath, actualpath);

      // TCP socket
      orig_socket_type socket_orig;
      socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
      fd = socket_orig(AF_INET, SOCK_STREAM, 0);
      if(fd == -1){
        printf("Error opening socket\n");
        return -1;
      }
      id  = concatenate(process_id, fd);
      global_id = id;
      netlink_connect(process_id);

      hashmap_add(sock_map, id, (void*)(long)fd);

      msg = nlmsg_alloc();
       if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
       }  
      msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_SOCKET_NOTIFY, 1);
      if (msg_head == NULL) {
        printf("Failed in genlmsg_put [socket notify]\n");
        nlmsg_free(msg);
        return -1;
      } 
      ret = nla_put_u64(msg, SSA_NL_A_ID, id);
      if (ret != 0) {
        printf("Failed in nla_put (id) [socket notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put_string(msg, SSA_NL_A_COMM, comm_ptr);
      if (ret != 0) {
        printf("Failed in nla_put (comm_ptr) [socket notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      nl_socket_set_peer_port(netlink_sock, 8443);
      ret = nl_send_auto(netlink_sock, msg);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1;
      }
      int response = recv_response();

      return fd;
  }
  else{
    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    return socket_orig(domain, type, protocol);
  }
}

int setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen){
    if(optname == 85){
      struct nl_msg* msg;
      int ret;
      void* msg_head;
      int id;
      msg = nlmsg_alloc();
        if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
       }
      msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_SETSOCKOPT_NOTIFY, 1);
      if (msg_head == NULL) {
        printf("Failed in genlmsg_put [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      id = global_id;
      ret = nla_put_u64(msg, SSA_NL_A_ID, id);
      if (ret != 0) {
        printf("Failed in nla_put (id) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put_u32(msg, SSA_NL_A_OPTLEVEL, level);
      if (ret != 0) {
        printf("Failed in nla_put (level) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put_u32(msg, SSA_NL_A_OPTNAME, optname);
      if (ret != 0) {
        printf("Failed in nla_put (optname) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put(msg, SSA_NL_A_OPTVAL, optlen, optval);
      if (ret != 0) {
        printf("Failed in nla_put (optval) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      nl_socket_set_peer_port(netlink_sock, 8443);
      ret = nl_send_auto(netlink_sock, msg);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1;
      }

      int response = recv_response();

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

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(hashmap_get(sock_map, global_id) != NULL){
    int bind_result;
    struct sockaddr_in local_address;
    struct nl_msg* msg;
    int ret;
    int id;
    void* msg_head;
    int blocking = 1;

    local_address.sin_family = AF_INET;
    local_address.sin_port = 0; // choose a random port
    local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 
    local_address_global = local_address;

    bind_result = bind(sockfd, (struct sockaddr*) &local_address, sizeof(local_address));
    if (bind_result == -1) {
      printf("Failed in bind\n");
      return -1;
    }
    socklen_t size = sizeof(local_address);
    getsockname(sockfd, (struct sockaddr *) &local_address, &size);

    // ------------------send the netlink message ------------------
    msg = nlmsg_alloc();
        if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
    }
    msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_CONNECT_NOTIFY, 1);
    if (msg_head == NULL) {
      printf("Failed in genlmsg_put [connect notify]\n");
      nlmsg_free(msg);
      return -1;
    } 
    id = global_id;
    ret = nla_put_u64(msg, SSA_NL_A_ID, id);
    if (ret != 0) {
      printf("Failed in nla_put (id) [connect notify]\n");
      nlmsg_free(msg);
      return -1;
    }
    ret = nla_put(msg, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), (struct sockaddr*) &local_address);
    if (ret != 0) {
      printf("Failed in nla_put (remote) [connect notify]\n");
      nlmsg_free(msg);
      return -1;
    }
    ret = nla_put(msg, SSA_NL_A_SOCKADDR_REMOTE, sizeof(struct sockaddr), addr);
    if (ret != 0) {
      printf("Failed in nla_put (internal) [connect notify]\n");
      nlmsg_free(msg);
      return -1;
    }
    ret = nla_put_u32(msg, SSA_NL_A_BLOCKING, blocking);
    if (ret != 0) {
      printf("Failed in nla_put (blocking) [connect notify]\n");
      nlmsg_free(msg);
      return -1;
    }
    nl_socket_set_peer_port(netlink_sock, 8443);
    ret = nl_send_auto(netlink_sock, msg);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1; 
      }
     nlmsg_free(msg);

     int response = recv_response(); //for connection

     int unlink = sem_unlink(SNAME);
     sem_t *sem_connect = sem_open(SNAME, O_CREAT, 0644, 0);
     int sem_value = sem_wait(sem_connect);
     int connection_check = make_connection(sockfd);
    
     if(connection_check == -1){
      return -1;
     }

     response = recv_response(); //for handshake response

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

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen){

  if(optname == SO_PEER_CERTIFICATE || optname == SO_PEER_IDENTITY){
      struct nl_msg* msg;
      int ret;
      void* msg_head;
      int id;
      msg = nlmsg_alloc();
        if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
       }
      msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_GETSOCKOPT_NOTIFY, 1);
      if (msg_head == NULL) {
        printf("Failed in genlmsg_put [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      id = global_id;
      ret = nla_put_u64(msg, SSA_NL_A_ID, id);
      if (ret != 0) {
        printf("Failed in nla_put (id) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put_u32(msg, SSA_NL_A_OPTLEVEL, level);
      if (ret != 0) {
        printf("Failed in nla_put (level) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put_u32(msg, SSA_NL_A_OPTNAME, optname);
      if (ret != 0) {
        printf("Failed in nla_put (optname) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      nl_socket_set_peer_port(netlink_sock, 8443);
      ret = nl_send_auto(netlink_sock, msg);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1;
      }

      int response = recv_response();
      strcpy(optval, global_data);

      return 0;
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
      struct nl_msg* msg;
      int ret;
      void* msg_head;
      int id;

      msg = nlmsg_alloc();
        if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
       }
      msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_CLOSE_NOTIFY, 1);
      if (msg_head == NULL) {
        printf("Failed in genlmsg_put [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      id = global_id;
      ret = nla_put_u64(msg, SSA_NL_A_ID, id);
      if (ret != 0) {
        printf("Failed in nla_put (id) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      nl_socket_set_peer_port(netlink_sock, 8443);
      ret = nl_send_auto(netlink_sock, msg);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1;
      }

      return 0;
  }
  else{
    printf("establishing normal close...\n");
    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    return close_orgi(fd);
  }
}

int listen(int sockfd, int backlog){
    printf("inject code on listen\n");
    orgi_listen_type listen_orgi;
    listen_orgi = (orgi_listen_type)dlsym(RTLD_NEXT,"listen");
    return listen_orgi(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
    printf("inject code on accept\n");
    orgi_accept_type accept_orgi;
    accept_orgi = (orgi_accept_type)dlsym(RTLD_NEXT,"accept");
    return accept_orgi(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
     printf("ssa bind is called\n");
     orgi_bind_type bind_orgi;
     bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
     return bind_orgi(sockfd, addr, addrlen);
}

/*
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  if(hashmap_get(sock_map, global_id) != NULL){
    printf("sockfd number: %d\n", sockfd);
    printf("hashmap: %d\n", hashmap_get(sock_map, global_id));
      struct nl_msg* msg;
      struct sockaddr_in local_address;
      int ret;
      void* msg_head;
      int id;

      msg = nlmsg_alloc();
        if (msg == NULL) {
        printf("Failed to allocate message buffer\n");
         return -1;
       }
      msg_head = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0, SSA_NL_C_BIND_NOTIFY, 1);
      if (msg_head == NULL) {
        printf("Failed in genlmsg_put [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      id = global_id;
      ret = nla_put_u64(msg, SSA_NL_A_ID, id);
      if (ret != 0) {
        printf("Failed in nla_put (id) [setsockopt notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      local_address = local_address_global;
      ret = nla_put(msg, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), (struct sockaddr*) &local_address);
      if (ret != 0) {
        printf("Failed in nla_put (remote) [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      ret = nla_put(msg, SSA_NL_A_SOCKADDR_REMOTE, sizeof(struct sockaddr), addr);
      if (ret != 0) {
        printf("Failed in nla_put (internal) [connect notify]\n");
        nlmsg_free(msg);
        return -1;
      }
      nl_socket_set_peer_port(netlink_sock, 8443);
      ret = nl_send_auto(netlink_sock, msg);

      printf("the ret number: %d\n", ret);
      if (ret < 0) {
        printf("Failed to send netlink msg\n");
        return -1;
      }
      
      printf("receive response on bind\n");
      //int response = recv_response();
      //printf("response number: %d\n", response);

      return 0;
  }
  else{
     orgi_bind_type bind_orgi;
     bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
     return bind_orgi(sockfd, addr, addrlen);
  }
}

*/
// need to prelaod the close socket function as well and delete the stored socket in the map
//gcc -shared -fPIC -ldl -lnl-3 -lnl-genl-3 -o socket_preload.so -I/usr/include/libnl3 socket_preload.c ../../hashmap.c
//gcc -shared -fPIC -ldl -lnl-3 -lnl-genl-3 -lpthread -lrt -o socket_preload.so -I/usr/include/libnl3 socket_preload.c ../../hashmap.c
