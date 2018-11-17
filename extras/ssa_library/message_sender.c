#include "message_sender.h" 

//create a new unix doamin socket and return the fd of that socket
int createUnixSocket(){
    int unix_fd;
    int ret;
    struct sockaddr_un addr;

    orig_socket_type socket_orig;
    socket_orig = (orig_socket_type)dlsym(RTLD_NEXT,"socket");
    if ((unix_fd = socket_orig(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
        perror("error in create socket.");
        return -1;
    }

    //bind with an random address
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, SOCKET_PRELOAD_FILE);
    ret = unlink(SOCKET_PRELOAD_FILE);
    orgi_bind_type bind_orgi;
    bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
    ret = bind_orgi(unix_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind failed");
        return -1;
    }

    // make the connection with the server side unix doamin socket
    memset(&addr, 0, sizeof(addr)); // to be deleted
    addr.sun_family = AF_UNIX; // to be deleted
    strcpy(addr.sun_path, SERVER_SOCK_FILE);
    orig_connect_type connect_orig;
    connect_orig = (orig_connect_type)dlsym(RTLD_NEXT,"connect");
    ret = connect_orig(unix_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        perror("connect failed in create unix socket");
        return -1;
    }
    return unix_fd;
}

int send_socket_message(unsigned long daemon_id){
	int ret;
	int len;
	char buff[8192];
	char idString[256];
    char unix_message[256];
    char *comm_ptr;
    char *symlinkpath = "/proc/self/exe";
    char actualpath [PATH_MAX+1];

    int unix_fd = createUnixSocket();

	// send ssa socket notify
    strcpy(buff, "1 ssa socket notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in socket");
        return -1;
    }
    // send id numeber
    strcpy(unix_message, "1id");
    sprintf(idString, "%ld", daemon_id); //convert daemon id to a string
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed socket");
        return -1;
    }
    //send daemon path
    strcpy(unix_message, "1pa");
    comm_ptr = realpath(symlinkpath, actualpath);
    comm_ptr = strcat(unix_message, comm_ptr);
    strcpy(buff, comm_ptr);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send comm_ptr failed in socket");
        return -1;
    }
    //the message come back from unix_server
    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received message for socket: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
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

int send_connect_message(int sockfd, unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr *addr){
    int ret;
    int len;
    char buff[8192];

    int unix_fd = createUnixSocket();

    // send connection notify
    strcpy(buff, "3 ssa connection notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }
    // send daemon id numeber
    char idString[256];
    char unix_message[256];
    strcpy(unix_message, "3id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }
    // send local address
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string(internal_address));
    strcpy(unix_message, "3la");
    strcat(unix_message, localAddressString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }
    // send remote address
    char addrString[256];
    strcpy(addrString, get_addr_string((struct sockaddr*) addr));
    strcpy(unix_message, "3ra");
    strcat(unix_message, addrString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send remote address failed");
        return -1;
    }
    // send blocking number
    char blockingString[256];
    strcpy(unix_message, "3bn");
    sprintf(blockingString, "%ld", 1);
    strcat(unix_message, blockingString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send blocking failed");
        return -1;
    }
    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received message for connection: %s\n", buff);

    //semaphore
    int unlink = sem_unlink(SNAME);
    sem_t *sem_connect = sem_open(SNAME, O_CREAT, 0644, 0);
    int sem_value = sem_wait(sem_connect);
    //make_connection with ssa daemon
    int connection_check = make_connection(sockfd); 
    if(connection_check == -1){
      return -1;
    }
    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("receive message for connection: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_setsockopt_message(unsigned long daemon_id, int level, int optname, char* optval_temp){
    int ret;
    int len;
    int unix_fd;
    char buff[8192];
    unix_fd = createUnixSocket();
    strcpy(buff, "2 ssa setsockpot notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in setsockopt");
        return -1;
    }

    // send id numeber
    char idString[256];
    char unix_message[256];
    strcpy(unix_message, "2id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }

    // send level
    char levelString[256];
    strcpy(unix_message, "2le");
    sprintf(levelString, "%ld", level);
    strcat(unix_message, levelString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send level failed");
        return -1;
    }

    // send option name
    char optnameString[256];
    strcpy(unix_message, "2on");
    sprintf(optnameString, "%ld", optname);
    strcat(unix_message, optnameString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send level failed");
        return -1;
    }

    printf("Option value: %s\n", optval_temp);

    // send optval
    strcpy(unix_message, "2ov");
    strcat(unix_message, optval_temp);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send optval failed");
        return -1;
    }

    free(optval_temp);

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }
    printf("received messgae for setsockopt: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_getsockopt_message(unsigned long daemon_id, int level, int optname, char* optval, socklen_t *optlen){
    int ret;
    int len;
    int unix_fd;
    char buff[8192];
    unix_fd = createUnixSocket();
    strcpy(buff, "4 ssa getsockopt notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in getsockopt");
        return -1;
    }

    // send id numeber
    char idString[256];
    char unix_message[256];
    strcpy(unix_message, "4id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }

    // send level
    char levelString[256];
    strcpy(unix_message, "4le");
    sprintf(levelString, "%ld", level);
    strcat(unix_message, levelString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send level failed");
        return -1;
    }

    // send option name
    char optnameString[256];
    strcpy(unix_message, "4on");
    sprintf(optnameString, "%ld", optname);
    strcat(unix_message, optnameString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send level failed");
        return -1;
    }

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    strncpy(optval, buff, *optlen); //copy returned buff to optval

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_close_message(unsigned long daemon_id){
    int ret;
    int len;
    char buff[8192];
    char idString[256];
    char unix_message[256];
    int unix_fd = createUnixSocket();
    strcpy(buff, "5 ssa close notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in close");
        return -1;
    }

    strcpy(unix_message, "5id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_accept_message(unsigned long new_daemon_id, struct sockaddr_in peer_address){
    int len;
    int ret;
    int unix_fd;
    char buff[8192];

    unix_fd = createUnixSocket();
    strcpy(buff, "6 ssa listen notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }

    // send id numeber
    char idString[256];
    char unix_message[256];
    strcpy(unix_message, "6id");
    sprintf(idString, "%ld", new_daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }

    //send peer address
    char addressString[256];
    strcpy(addressString, get_addr_string((struct sockaddr*)&peer_address));
    strcpy(unix_message, "6la");
    strcat(unix_message, addressString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_listen_message(unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr* external_address){
    int len;
    int ret;
    int unix_fd;
    char buff[8192];
    char idString[256];
    char unix_message[256];

    unix_fd = createUnixSocket();
    strcpy(buff, "7 ssa listen notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send connection message failed");
        return -1;
    }
    // send id numeber
    strcpy(unix_message, "7id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send id failed in setsockopt");
        return -1;
    }
    // send local address
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string(internal_address));
    strcpy(unix_message, "7la");
    strcat(unix_message, localAddressString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }
    // send external address
    char addrString[256];
    strcpy(addrString, get_addr_string(external_address));
    strcpy(unix_message, "7ea");
    strcat(unix_message, addrString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send remote address failed");
        return -1;
    }
    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
        perror("recv error");
        return -1;
    }

    printf("the messgae received in listen: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}

int send_bind_message(unsigned long daemon_id, struct sockaddr* internal_address, struct sockaddr* external_address){
    int unix_fd;
    int ret;
    int len;
    char buff[8192];
    unix_fd = createUnixSocket();
    strcpy(buff, "8 ssa close notify");
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send failed in close");
        return -1;
    }

    // send id numeber
    char idString[256];
    char unix_message[256];
    strcpy(unix_message, "8id");
    sprintf(idString, "%ld", daemon_id);
    strcat(unix_message, idString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) { // send can be used when a socket is in a connected state
        perror("send id failed in setsockopt");
        return -1;
    }

    // send local address (aka internal address)
    char localAddressString[256];
    strcpy(localAddressString, get_addr_string(internal_address));
    strcpy(unix_message, "8la");
    strcat(unix_message, localAddressString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send local address failed");
        return -1;
    }

    // send external address
    char addrString[256];
    strcpy(addrString, get_addr_string(external_address));
    strcpy(unix_message, "8ea");
    strcat(unix_message, addrString);
    strcpy(buff, unix_message);
    ret = send(unix_fd, buff, strlen(buff)+1, 0);
    if (ret == -1) {
        perror("send external address failed");
        return -1;
    }

    if ((len = recv(unix_fd, buff, 8192, 0)) < 0) {
    perror("recv error");
    return -1;
    }

    printf("the messgae received in bind: %s\n", buff);

    orgi_close_type close_orgi;
    close_orgi = (orgi_close_type)dlsym(RTLD_NEXT,"close");
    close_orgi(unix_fd);

    return 0;
}