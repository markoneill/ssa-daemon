#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <unistd.h>
#include "unix_server.h"

int global_fd;
int bind_check;
int global_level;
int global_optname;
unsigned long global_id;
struct sockaddr_in addr_internal;
struct sockaddr_in addr_remote;
struct sockaddr_in addr_external;
struct sockaddr_un destination_address;

typedef int (*orgi_bind_type)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

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
    sprintf(portString, "%d", port);
    strcat(str, semicolon);
    strcat(str, portString);

    printf("the Address: %s\n", str);

    char *result = malloc(sizeof(str));
    memcpy(result, str, sizeof(str));

    return result;
}

void chopString(char *str, size_t n)
{
    assert(n != 0 && str != 0);
    size_t len = strlen(str);
    if (n > len)
        return;  // Or: n = len;
    memmove(str, str+n, len - n + 1);
}

int create_unix_socket(){
	int fd;
	int ret;
	struct sockaddr_un addr;
	// create unix socket
	if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("create socket failed");
		return -1;
	}
	global_fd = fd;
	bind_check = 0;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SERVER_SOCK_FILE);
	orgi_bind_type bind_orgi;
    bind_orgi = (orgi_bind_type)dlsym(RTLD_NEXT,"bind");
    ret = bind_orgi(global_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
	perror("bind failed");
	return -1;
	}
    
    char *path = "/tmp/server.sock";
    char mode[] = "0777";
    int i;
    i = strtol(mode, 0, 8);
    ret = chmod(path, i);
    if(ret < 0){
    	perror("chomod failed");
    	return -1;
    }

    // print out the permission
    struct stat *buf;
    buf = malloc(sizeof(struct stat));
    ret = stat(path, buf);
    printf( (S_ISDIR(buf->st_mode)) ? "d" : "-");
    printf( (buf->st_mode & S_IRUSR) ? "r" : "-");
    printf( (buf->st_mode & S_IWUSR) ? "w" : "-");
    printf( (buf->st_mode & S_IXUSR) ? "x" : "-");
    printf( (buf->st_mode & S_IRGRP) ? "r" : "-");
    printf( (buf->st_mode & S_IWGRP) ? "w" : "-");
    printf( (buf->st_mode & S_IXGRP) ? "x" : "-");
    printf( (buf->st_mode & S_IROTH) ? "r" : "-");
    printf( (buf->st_mode & S_IWOTH) ? "w" : "-");
    printf( (buf->st_mode & S_IXOTH) ? "x" : "-");
    printf("\n");

	return fd;
}

void unix_recv(evutil_socket_t fd, short events, void *arg) {
	tls_daemon_ctx_t* ctx = (tls_daemon_ctx_t*)arg;
	int unix_fd;
	int len;
	int blocking;

    char messageBuff[8192];
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	unsigned long id;
	char comm[PATH_MAX];
	char *id_ptr;
	char *level_ptr;
	char *optname_ptr;
	char *blocking_ptr;
	socklen_t optlen;

	struct sockaddr_in addr_remote;
	int addr_internal_len;
	int addr_external_len;
	int addr_remote_len;

	unix_fd = global_fd;
	
	len = recvfrom(unix_fd, messageBuff, 8192, 0, (struct sockaddr *)&from, &fromlen);// get rid of the shile loop
	//printf("size of: %d\n", len);
	char buff[len];
	strcpy(buff, messageBuff);
	if(len < 0){
		perror("message receive failed");
		return;
	}
	destination_address = from;
	if(buff[0] == '1'){ // a socket notify
		if(buff[1] == 'i' && buff[2] == 'd'){
			char *ptr;
			chopString(buff, 3);
			id = strtoul(buff, &ptr, 10);
			global_id = id;
			}
		else if(buff[1] == 'p' && buff[2] == 'a'){ // last message to receive
            chopString(buff, 3);
            memcpy(comm, buff, sizeof(buff));
            socket_cb(ctx, global_id, comm);
		}
		else{
			printf("received socket notification\n");
		}
	}
	else if(buff[0] == '2'){ // a set sockopt notification 
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'e'){
			chopString(buff, 3);
			global_level = strtoul(buff, &level_ptr, 10);
		}
		else if(buff[1] == 'o' && buff[2] == 'n'){
			chopString(buff, 3);
			global_optname = strtoul(buff, &optname_ptr, 10);
		}
		else if(buff[1] == 'o' && buff[2] == 'v'){
			chopString(buff, 3);
            optlen  = (socklen_t)sizeof(buff); 
			setsockopt_cb(ctx, global_id, global_level, global_optname, buff, optlen);
		}
		else{
			printf("received set sockopt notification\n");
		}
	}
	else if(buff[0] == '3'){ // connection notification
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_internal, '\0', sizeof(addr_internal));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

			addr_internal.sin_family = AF_INET;
			addr_internal.sin_port = htons(port_number);
			inet_aton(address, &addr_internal.sin_addr);
		}
		else if(buff[1] == 'r' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_remote, '\0', sizeof(addr_remote));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

            addr_remote.sin_family = AF_INET;
			addr_remote.sin_port = htons(port_number);
			inet_aton(address, &addr_remote.sin_addr);
		}
		else if(buff[1] == 'b' && buff[2] == 'n'){
			chopString(buff, 3);
			blocking = strtoul(buff, &blocking_ptr, 10);
			addr_internal_len = sizeof(addr_internal);
			addr_remote_len = sizeof(addr_remote);
			connect_cb(ctx, global_id, (struct sockaddr*)&addr_internal, addr_internal_len,
					    (struct sockaddr*)&addr_remote, addr_remote_len, blocking);
		}
		else{
			printf("Received connection notification\n");
		}
	}
	else if(buff[0] == '4'){ // get sock opt
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'e'){
			chopString(buff, 3);
			global_level = strtoul(buff, &level_ptr, 10);
		}
		else if(buff[1] == 'o' && buff[2] == 'n'){
			chopString(buff, 3);
			global_optname = strtoul(buff, &optname_ptr, 10);
			getsockopt_cb(ctx, global_id, global_level, global_optname);
		}
		else{
			printf("Received getsockopt notification\n");
		}
	}
	else if(buff[0] == '5'){
	   if(buff[1] == 'i' && buff[2] == 'd'){
	   	printf("close id number: %s\n", buff);
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
			close_cb(ctx, global_id);
	   }
	   else{
	   	   printf("Received close notification\n");
	   }
	}
	else if(buff[0] == '6'){ // accept
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'a'){
			printf("accept local address: %s\n", buff);
            chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_internal, '\0', sizeof(addr_internal));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

			addr_internal.sin_family = AF_INET;
			addr_internal.sin_port = htons(port_number);
			inet_aton(address, &addr_internal.sin_addr);

			addr_internal_len = sizeof(addr_internal);

            associate_cb(ctx, global_id, (struct sockaddr*)&addr_internal, addr_internal_len);
		}
		else{
			printf("Received accept notification\n");
		}
	}
	else if(buff[0] == '7'){// listen
        if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_internal, '\0', sizeof(addr_internal));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

			addr_internal.sin_family = AF_INET;
			addr_internal.sin_port = htons(port_number);
			inet_aton(address, &addr_internal.sin_addr);
		}
		else if(buff[1] == 'e' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_external, '\0', sizeof(addr_external));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

            addr_external.sin_family = AF_INET;
			addr_external.sin_port = htons(port_number);
			inet_aton(address, &addr_external.sin_addr);

			addr_internal_len = sizeof(addr_internal);
			addr_external_len = sizeof(addr_external);

			listen_cb(ctx, global_id, (struct sockaddr*)&addr_internal, addr_internal_len,
			(struct sockaddr*)&addr_external, addr_external_len);
		}
		else{
			printf("Received listen notification\n");
		}
	}
	else if(buff[0] == '8'){ // bind
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			global_id = strtoul(buff, &id_ptr, 10);
		}
		else if(buff[1] == 'l' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_internal, '\0', sizeof(addr_internal));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

			addr_internal.sin_family = AF_INET;
			addr_internal.sin_port = htons(port_number);
			inet_aton(address, &addr_internal.sin_addr);
		}
		else if(buff[1] == 'e' && buff[2] == 'a'){
			chopString(buff, 3);
			char* address;
			char* port_string;
			char *port_ptr;
			int port_number;
			memset(&addr_external, '\0', sizeof(addr_external));
			address = strtok(buff, ":");
			port_string = strtok(NULL, ":");
            port_number = strtoul(port_string, &port_ptr, 10);

            addr_external.sin_family = AF_INET;
			addr_external.sin_port = htons(port_number);
			inet_aton(address, &addr_external.sin_addr);

			addr_internal_len = sizeof(addr_internal);
			addr_external_len = sizeof(addr_external);
            
			bind_cb(ctx, global_id, (struct sockaddr*)&addr_internal, addr_internal_len,
			(struct sockaddr*)&addr_external, addr_external_len);
		}
		else{
			printf("Received bind notification\n");
		}
	}
	else{
		printf("unkonw message: %s\n", buff);
		return;
	}

	return;
}

int close_unix_socket(int fd){
	printf("close unix sock and unlink the file.\n");
	unlink(SERVER_SOCK_FILE);
    return close(fd);
}

// type one need to send a id and response back
void unix_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response) {
	int ret;
	int fd;
	char idString[256];
    char responseString[256];
    char result[256];
    char buff[8192];
	socklen_t len = sizeof(destination_address);

	fd = global_fd;

    strcpy(result, "1,");
    sprintf(idString, "%ld", id);
    sprintf(responseString, "%d", response);
    strcat(result, responseString);
    strcat(result, ",");
    strcat(result, idString);
    strcpy(buff, result);
    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, len);
    if (ret < 0) {
    perror("failed in unix notify kernel");
    return;
    }
    else{
    	printf("unix notify kernel successful\n");
    }
	return;
}

//type two need to send id and data back
void unix_send_and_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, char* data, unsigned int len) {
	int ret;
	int fd;
    char idString[256];
    char result[8192];
    char buff[8192];
    socklen_t address_len = sizeof(destination_address);

    fd = global_fd;

    memset(result, 0, sizeof(result));
    sprintf(idString, "%ld", id);
    strcat(result, idString);
    strcat(result, ",");
    strcat(result, data);
    strcpy(buff, result);

    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, address_len);
    if (ret < 0) {
    perror("failed in unix send and notify sendto");
    return;
    }
    else{
    	printf("unix send and notify kernel successful\n");
    }
	return;
}

//type 3 is the hand shake response
void unix_handshake_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response) {
	int ret;
    int fd;
	char idString[256];
    char responseString[256];
    char result[256];
    char buff[8192];
	socklen_t len = sizeof(destination_address);

	fd = global_fd;

    strcpy(result, "3,");
    sprintf(idString, "%ld", id);
    sprintf(responseString, "%d", response);
    strcat(result, responseString);
    strcat(result, ",");
    strcat(result, idString);
    strcpy(buff, result);
    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, len);
    if (ret < 0) {
    perror("failed in sendto");
    return;
    }
    else{
    	printf("unix handshake notify kernel successful\n");
    }
	return;
}
