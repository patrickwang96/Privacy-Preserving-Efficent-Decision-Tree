//
// Created by Ruochen WANG on 2/4/2020.
//

#include "test_driver.h"

int main() {
//    test_cloud_client(1);
    std::vector<int> test = {1, 2, 3};
    test_cloud_client_by_parts(test, 1);
    return 0;
}
