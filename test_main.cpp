//
// Created by Ruochen WANG on 2/4/2020.
//

#include "network.h"
#include <iostream>

using namespace std;
int main() {
    NetAdapter* server = new NetAdapter(0);
    NetAdapter* client = new NetAdapter(1);

    int data = 2;
    int buffer;

    client->send(reinterpret_cast<const char *>(&data), sizeof(data));
    server->recv(reinterpret_cast<char *>(&buffer), sizeof(data));

    cout << buffer << endl;

    return 0;

}
