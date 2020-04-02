//
// Created by Ruochen WANG on 25/3/2020.
//

#include "network.h"


void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

void client_init(int *client_fd) {
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(SERV_ADDR, SERV_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "Getaddrinfo: %s\n", gai_strerror(rv));
        return;
    }

    // Loop through all the results and connect to the first we can
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        *client_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (*client_fd == -1) {
            perror("client: socket");
            continue;
        }

        int ret = connect(*client_fd, p->ai_addr, p->ai_addrlen);
        if (ret == -1) {
            close(*client_fd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == nullptr) {
        fprintf(stderr, "client: failed to connect\n");
        return;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *) p->ai_addr), s, sizeof(s));
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo);
}

void client_close(int client_fd) {
    if (close(client_fd) != 0) perror("client close went wrong");
    else printf("client closed\n");
}

void server_init(int *server_fd) {
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo hints, *res, *p;
    int sockfd = -1;
    char s[INET6_ADDRSTRLEN];
    int yes;

    memset(&hints, 0, sizeof(hints));
    hints.ai_addr = reinterpret_cast<sockaddr *>(AF_INET);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int status = getaddrinfo(nullptr, SERV_PORT, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "get addr info error: %s\n", gai_strerror(status));
        exit(1);
    }

    for (p = res; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("server: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (p == nullptr) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    for (;;) { // main accept() loop
        addr_size = sizeof(their_addr);
        *server_fd = accept(sockfd, (struct sockaddr *) &their_addr, &addr_size);
        if (*server_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *) &their_addr), s, sizeof(s));
        printf("server: got connection from %s\n", s);
        close(sockfd);
        break;
    }
}

void server_close(int server_fd) {
    if (close(server_fd) != 0) perror("server close");
    else printf("server closed\n");
}

NetAdapter::NetAdapter(int id) {
    this->id = id;
    this->recv_bytes = 0;
    this->send_bytes = 0;
    this->isOpen = false;
    if (this->id == 1) {
        // id = 1 is set to client
        client_init(&this->fd);
    }
    else server_init(&this->fd);
}

NetAdapter::~NetAdapter() {
    if (this->id == 1) client_close(this->fd);
    else server_close(this->fd);
}

void NetAdapter::send(const char *data, uint64_t size) {
    int nwritten, totlen = 0;
    while (totlen != size) {
        nwritten = write(fd, data, size - totlen);
        if (nwritten == 0) return ;
        if (nwritten == -1) return ;
        totlen += nwritten;
        data += nwritten;
        this->send_bytes += nwritten;
    }
}

void NetAdapter::recv(char *data, uint64_t size) {
    int nread, totlen = 0;
    while (totlen != size) {
        nread = read(fd, data, size - totlen);
        if (nread == 0) return ;
        if (nread == -1) return ;
        totlen += nread;
        data += nread;
        this->recv_bytes += nread;
    }
}

unsigned long long NetAdapter::get_send_bytes() {
    return this->send_bytes;
}

unsigned long long NetAdapter::get_rev_bytes() {
    return this->recv_bytes;
}
