//
// Created by Ruochen WANG on 1/4/2020.
//

#include "secret_sharing.h"
#include "utils.h"
#include "decision_tree.h"

#include <chrono>
#include <math.h>
#include <vector>
#include "network.h"
#include <iostream>

extern gmp_randclass gmp_prn;

extern std::chrono::steady_clock::time_point start, end;
#define CLOCK_START {start = std::chrono::steady_clock::now();}
#define CLOCK_END {end = std::chrono::steady_clock::now();}
#define ELAPSED std::chrono::duration<double, std::nano>(end - start).count()

void phase2(NetAdapter *net, int num_trial);

void test_cloud_client_by_parts(std::vector<int> phases, int num_trial) {
    // m: decision node
    int n, m;
    NetAdapter *net = new NetAdapter(1);

    for (auto phase: phases) {
        if (phase == 1) {
          std::cout << "Reached phase 1." << std::endl;
        } else if (phase == 2) {
            phase2(net, num_trial);
        } else if (phase == 3) {
          std::cout << "Reached phase 3." << std::endl;
        }
    }

    net->close();
}

void phase2(NetAdapter *net, int num_trial) {
    int n, m;
    // secure node evaluation
//    NetAdapter* net = new NetAdapter(0);
    triplet_b tri_b;
    triplet_z tri_z;
    for (int i = 0; i < 5; ++i) {
        n = param_nd[i][0];
        m = pow(2, param_nd[i][1]) - 1;

        // ugly staff for preparation
        mpz_class (*x) = new mpz_class[m], (*y) = new mpz_class[m];
        for (int j = 0; j < m; ++j) {
            x[j] = gmp_prn.get_z_bits(CONFIG_L);
            y[j] = gmp_prn.get_z_bits(CONFIG_L);
        }

        double time_total = 0;
        unsigned long long send_bytes = net->get_send_bytes();
        unsigned long long recv_bytes = net->get_rev_bytes();

        for (int j = 0; j < num_trial; ++j) {
            CLOCK_START
//            for (int k = 0; k < m; ++k)
            secure_node_eval_with_look_ahead_carry_adder_client(x, y, m, tri_z, tri_b, net);
            CLOCK_END
            time_total += ELAPSED;

            cache_flusher();
        }
        send_bytes = net->get_send_bytes() - send_bytes;
        recv_bytes = net->get_rev_bytes() - recv_bytes;
        send_bytes /= num_trial;
        recv_bytes /= num_trial;
        double send_mb = send_bytes / 1024.0 / 1024.0;
        double recv_mb = recv_bytes / 1024.0 / 1024.0;

        printf("secure node evaluation (n=%d, d=%d, m=%d): %f ns, send_bytes: %f MB, recv bytes: %f MB\n", n,
               param_nd[i][1], m,
               time_total / num_trial, send_mb * 2, recv_mb); // count only one party

        delete[] x;
        delete[] y;
    }
}

