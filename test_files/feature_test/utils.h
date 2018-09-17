#ifndef UTILS_H

#define CERT_FILE_A	"../certificate_a.pem"
#define KEY_FILE_A	"../key_a.pem"
#define CERT_FILE_B	"../certificate_b.pem"
#define KEY_FILE_B	"../key_b.pem"

#define LARGE_BUFFER	2048

int connect_to_host(char* host, char* service);
int bind_listen(uint16_t port, char* hostname);
int echo_recv(int fd, char* buff, size_t buff_len);
//int timed_accept(int listen_fd, struct sockaddr* addr, socklen_t* addr_len, int timeout);

#endif //UTILS_H
