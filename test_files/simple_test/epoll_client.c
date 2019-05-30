/* Mass connection client using edge-triggered epoll */
/* Run a corresponding server with ncat -l 8080 -k -c 'xargs -l1 echo' */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <fcntl.h>
#include "../../in_tls.h"

#define BUFFER_MAX	1024
#define MAX_EVENTS	500
#define REPEATS		0

typedef enum state {
	CONNECTING,
	SENDING,
	RECEIVING,
	DISCONNECTED,
} state_t;

typedef struct connection {
	int id;
	int fd;
	int counter;
	state_t state;
	char w_buf[BUFFER_MAX];
	char r_buf[BUFFER_MAX];
	int w_buf_pos;
	int r_buf_pos;
} connection_t;

int connect_to_host(char* host, char* port, int prot);
int set_blocking(int sock, int blocking);
int send_data(connection_t* conn);
int recv_data(connection_t* conn);
int is_connected(int fd);

int main(int argc, char* argv[]) {
	int i;
	int n;
	int nfds;
	char host[] = "www.phoenixteam.net";

	/* Set up polling */
	struct epoll_event ev;
	struct epoll_event events[MAX_EVENTS];
	
	int epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	/* Create connections */
	int num_connections = atoi(argv[1]);
	connection_t* connections = (connection_t*)calloc(num_connections, sizeof(connection_t));
	for (i = 0; i < num_connections; i++) {
		connections[i].state = CONNECTING;
		connections[i].id = i;
		connections[i].fd = connect_to_host(host, "443", SOCK_STREAM);
		ev.events = EPOLLOUT | EPOLLHUP | EPOLLET;
		ev.data.ptr = (void*)&connections[i];
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connections[i].fd, &ev) == -1) {
			perror("epoll_ctl add");
			exit(EXIT_FAILURE);
		}
		//sprintf(connections[i].w_buf, "Client %d says hello\n", connections[i].id);
		sprintf(connections[i].w_buf, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host);
	}
	

	/* Event Loop */
	while (1) {
	
		/* Wait for events, indefinitely */
		nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}

		for (n = 0; n < nfds; n++) {
			connection_t* conn = (connection_t*)events[n].data.ptr;
			if (events[n].events & EPOLLRDHUP) {
				printf("Disconnected\n");
				conn->state = DISCONNECTED;
			}
			if (events[n].events & EPOLLOUT) {
				if (conn->state == CONNECTING) {
					if (is_connected(conn->fd) == 1) {
						printf("Nonblocking connect finished\n");
						conn->state = SENDING;
					}
					else {
						continue;
					}
				}
				if (send_data(conn) == 0) {
					ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
					ev.data.ptr = (void*)conn;
					epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
				}
			}
			if (events[n].events & EPOLLIN) {
				if (recv_data(conn) == 0) {
					ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLET;
					ev.data.ptr = (void*)conn;
					epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev);
				}
			}
			if (conn->state == DISCONNECTED) {
				if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL) == -1) {
					perror("epoll_ctl: removing connection");
					exit(EXIT_FAILURE);
				}
				printf("[conn completed] [client %d] Disconnecting\n", conn->id);
				close(conn->fd);
				num_connections--;
			}

		}
		if (num_connections == 0) break;
	}
	free(connections);
	return 0;
}

int send_data(connection_t* conn) {
	if (conn->state != SENDING) return 0;
	int pos = conn->w_buf_pos;
	int bytes_to_write = strlen(&conn->w_buf[conn->w_buf_pos]);
	int bytes_written;
	while (bytes_to_write > 0) {
		bytes_written = send(conn->fd, conn->w_buf + pos, bytes_to_write, 0);
		if (bytes_written == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->w_buf_pos = pos;
				return 1;
			}
			perror("send");
			return -1;
		}
		bytes_to_write -= bytes_written;
		pos += bytes_written;
	}
	conn->state = RECEIVING;
	printf("[send completed] [client %d] %s", conn->id, conn->w_buf);
	memset(conn->w_buf, 0, BUFFER_MAX);
	conn->w_buf_pos = 0;
	return 0;
}

int recv_data(connection_t* conn) {
	if (conn->state != RECEIVING) return 0;
	int pos = conn->r_buf_pos;
	char* newline_ptr;
	int bytes_read;
	int total_bytes_read = 0;
	while ((newline_ptr = strchr(conn->r_buf, '\n')) == NULL) {
		int bytes_read = recv(conn->fd, conn->r_buf + pos, BUFFER_MAX - (pos + 1), 0);
		if (bytes_read == 0) {
			conn->state = DISCONNECTED;
			return 0;
		}
		if (bytes_read == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->r_buf_pos = pos;
				return 1;
			}
			perror("recv");
			return -1;
		}
		total_bytes_read += bytes_read;
		pos += bytes_read;
	}
	*newline_ptr = '\0';
	printf("[recv completed] [client %d] %s\n", conn->id, conn->r_buf);
	//conn->state = SENDING;
	memset(conn->r_buf, 0, BUFFER_MAX);
	conn->r_buf_pos = 0;
	sprintf(conn->w_buf, "Client %d says hello again (count = %d)\n", conn->id, conn->counter++);
	if (conn->counter > REPEATS) {
		conn->state = DISCONNECTED;
	}
	return 0;
}

int set_blocking(int sock, int blocking) {
	int flags;
	/* Get flags for socket */
	if ((flags = fcntl(sock, F_GETFL)) == -1) {
		perror("fcntl get");
		exit(EXIT_FAILURE);
	}
	/* Only change flags if they're not what we want */
	if (blocking && (flags & O_NONBLOCK)) {
		if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) == -1) {
			perror("fcntl set block");
			exit(EXIT_FAILURE);
		}
		return 0;
	}
	/* Only change flags if they're not what we want */
	if (!blocking && !(flags & O_NONBLOCK)) {
		if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
			perror("fcntl set nonblock");
			exit(EXIT_FAILURE);
		}
		return 0;
	}
	return 0;
}

int connect_to_host(char* host, char* service, int prot) {
	int sock;
	int ret;
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = prot; // Typically TCP
	hints.ai_family = AF_INET; // IP4
	ret = getaddrinfo(host, service, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock == -1) {
			perror("socket");
			continue;
		}
		setsockopt(sock, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1);
		set_blocking(sock, 0);
		if (connect(sock, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			if (errno == EINPROGRESS || errno == EALREADY) {
				printf("Couldn't connect immediately\n");
			}
		}
		break;
	}
	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "Failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}
	return sock;
}

int is_connected(int fd) {
/*	int connected;
	int error;
	socklen_t errorlen = sizeof(error);
	connected = 0;
	printf("Checking\n");
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errorlen) == -1) {
		perror("SOL_SOCKET");
		exit(EXIT_FAILURE);
	}
	printf("Error is %s\n", strerror(error));
	if (error == 0) {
		connected = 1;
	}
	return connected;
*/

	struct sockaddr_in peer_addr;
	socklen_t peer_addrlen = sizeof(peer_addr);
	return (getpeername(fd, (struct sockaddr*)&peer_addr, &peer_addrlen) == 0);
}

