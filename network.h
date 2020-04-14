//
// Created by Ruochen WANG on 25/3/2020.
//

#ifndef PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_NETWORK_H
#define PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_NETWORK_H

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>

//#include <pthread>
//#include <sys/time.h>

#define SERV_ADDR "localhost"
#define SERV_PORT "1245"
#define BACKLOG 10
#define HOST_ID 1

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define timeval_t struct timeval

void client_init(int *client_fd);

void client_close(int client_fd);

void server_init(int *server_fd);

void server_close(int server_fd);

class NetAdapter {
private:
    int fd;
    int id;
    bool isOpen;
    unsigned long long send_bytes;
    unsigned long long recv_bytes;

public:
    NetAdapter(int id);

    ~NetAdapter();

    void send(unsigned char *data, uint64_t size);

    void recv(unsigned char *data, uint64_t size);

    unsigned long long get_send_bytes();

    unsigned long long get_rev_bytes();

    void close();

};

#endif //PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_NETWORK_H
