//
// Created by Ruochen WANG on 2/4/2020.
//

#include "test_driver.h"

int main() {
//    test_cloud_server(1);
    std::vector<int> test = {2};
    test_cloud_server_by_parts(test, 1);

    // test_client(1);
    // test_sp(1);
    return 0;
}
