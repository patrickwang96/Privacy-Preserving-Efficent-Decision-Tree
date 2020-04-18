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
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/NChooseOne//Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/Base/SimplestOT.h"

extern gmp_randclass gmp_prn;

extern std::chrono::steady_clock::time_point start, end;
#define CLOCK_START {start = std::chrono::steady_clock::now();}
#define CLOCK_END {end = std::chrono::steady_clock::now();}
#define ELAPSED std::chrono::duration<double, std::nano>(end - start).count()

using namespace osuCrypto;


void
phase1(int n, int m, NetAdapter *net, int num_trial, KkrtNcoOtSender &sender, KkrtNcoOtReceiver &receiver, PRNG &prng,
       Channel &chl);

void phase2(NetAdapter *net, int num_trial);

void phase3(NetAdapter *net, int num_trial);

void test_cloud_client_by_parts(std::vector<int> phases, int num_trial) {
    // m: decision node
    int n, m;
    NetAdapter *net = new NetAdapter(1);

    for (auto phase: phases) {
        if (phase == 1) {
            IOService ios(10);
            PRNG prng(sysRandomSeed());
            Session client(ios, OT_ADDR, SessionMode::Client, "");
//    Channel chl(ios, new SocketAdapter<NetAdapter> (*net));
            Channel chl = client.addChannel();
            KkrtNcoOtSender sender;
            KkrtNcoOtReceiver receiver;
            bool maliciousSecure = false;
            uint64_t statSecParam = 40;
            uint64_t inputBitCount = 128;
            sender.configure(maliciousSecure, statSecParam, inputBitCount);
            receiver.configure(maliciousSecure, statSecParam, inputBitCount);

            sender.genBaseOts(prng, chl);
            receiver.genBaseOts(prng, chl);

            for (int i = 0; i < 5; i++) {
                n = param_nd[i][0];
                m = pow(2, param_nd[i][1]) - 1;
                phase1(n, m, net, num_trial, sender, receiver, prng, chl);
            }
//        net->close();
        } else if (phase == 2) {
            phase2(net, num_trial);
        } else if (phase == 3) {
            phase3(net, num_trial);
        }
    }

    net->close();
}

void
phase1(int n, int m, NetAdapter *net, int num_trial, KkrtNcoOtSender &sender, KkrtNcoOtReceiver &receiver, PRNG &prng,
       Channel &chl) {
//    int n, m;
//    NetAdapter* net = new NetAdapter(0);
    // secure input selection

//    ss_tuple_mz sel_ind(m, 1); // I feature selection vector
//    ss_tuple_mz x(n, 1); //feature vector
//    set_selection_index(sel_ind.plain, n);
//    sel_ind.encrypt();
//    x.encrypt();

    std::vector<uint64_t> x(n);
    std::vector<uint64_t> sel_ind(m);

    std::vector<uint64_t> selected_feature(m);

    double time_total = 0;
    unsigned long long send_bytes = net->get_send_bytes();
    unsigned long long recv_bytes = net->get_rev_bytes();

    for (int j = 0; j < num_trial; j++) {
        CLOCK_START
        secure_feature_selection_with_one_node_client(x, sel_ind, selected_feature[0], 0, net, sender, receiver, prng,
                                                      chl);
        CLOCK_END
    }
    time_total += ELAPSED;
    send_bytes = net->get_send_bytes() - send_bytes;
    recv_bytes = net->get_rev_bytes() - recv_bytes;
    send_bytes /= num_trial;
    recv_bytes /= num_trial;
    double send_mb = send_bytes / 1024.0 / 1024;
    double recv_mb = recv_bytes / 1024.0 / 1024.0;
    cache_flusher();

    printf("secure node selection (n=%d, m=%d): %f ns, send bytes: %f MB, recv bytes: %f MB\n", n, m,
           time_total / num_trial, send_mb * 2, recv_mb); // count only one party
//        delete[]selected_feature;
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


void phase3(NetAdapter *net, int num_trial) {
    // secure inference generation

    int n, m;
//    NetAdapter* net = new NetAdapter(0);
    int d;
    triplet_b tri_b;
    triplet_z tri_z;
    for (int i = 0; i < 5; ++i) {
        n = param_nd[i][0];
        d = param_nd[i][1];

        int num_of_edge = (1 << d) - 1;
        int num_of_leaf = num_of_edge + 1;

        auto decision = new int[num_of_edge];
        auto value = new mpz_class[num_of_leaf];
//        auto result = new mpz_class[2];
        mpz_class result;

        double time_total = 0;
        unsigned long long send_bytes = net->get_send_bytes();
        unsigned long long recv_bytes = net->get_rev_bytes();

        for (int j = 0; j < num_trial; ++j) {
            CLOCK_START
            secure_inference_generation_client(decision, value, d, result, tri_b, tri_z, net);
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

        printf("secure inference generation (n=%d, d=%d): %f ns, send bytes: %f MB, recv bytes: %f MB\n", n, d,
               time_total / num_trial, send_mb * 2, recv_mb); // one party
        delete[] decision;
        delete[] value;
//        delete[] result;
    }
//    net->close();
}

