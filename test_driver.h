#ifndef TEST_DRIVER_H
#define TEST_DRIVER_H

#include <vector>

void test_client(int num_trial);

void test_sp(int num_trial);

void test_cloud(int num_trial);

void test_cloud_client(int num_trial);

void test_cloud_server(int num_trial);

void test_cloud_server_by_parts(std::vector<int> phases, int num_trail);

void test_cloud_client_by_parts(std::vector<int> phases, int num_trail);
#endif