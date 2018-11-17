#include "unix_helper.h" 

//concatenate two number to gether fpr example pass in 1, 2  comes out 12
unsigned long concatenate(unsigned long x, int y) { 
    unsigned long pow = 10;
    while(y >= pow){
      pow *= 10;
    }
    return x * pow + y;
}

int is_valid_host_string(char* str, int len) {
    int i;
    char c;
    for (i = 0; i < len-1; i++) {
        c = str[i];
                if (!isalnum(c) && c != '-' && c != '.') {
            return 0;
                }
        }
    if (str[len-1] != '\0') {
        return 0;
    }
        return 1;
}

/*
funtion return an address string
*/
char* get_addr_string(struct sockaddr *addr) {
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

    char *result = malloc(sizeof(str));
    memcpy(result, str, sizeof(str));

    return result;
}


void put_tls_sock_data(hmap_t* sock_map, unsigned long key, tls_sock_data_t* sock_data) {
    //spin_lock(&tls_sock_data_table_lock);
    hashmap_add(sock_map, key, sock_data); // key and value
    //spin_unlock(&tls_sock_data_table_lock);
    return;
}

tls_sock_data_t* get_tls_sock_data(hmap_t* sock_map, unsigned long key) {
    return hashmap_get(sock_map, key);
}
