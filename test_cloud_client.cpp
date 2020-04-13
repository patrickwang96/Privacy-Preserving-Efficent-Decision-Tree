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

extern gmp_randclass gmp_prn;

const int param_nd[5][2] = {{9,  8},
                            {13, 3},
                            {13, 13},
                            {15, 4},
                            {57, 17}};

//auto start = std::chrono::steady_clock::now(), end = std::chrono::steady_clock::now();
extern std::chrono::steady_clock::time_point start, end;
#define CLOCK_START {start = std::chrono::steady_clock::now();}
#define CLOCK_END {end = std::chrono::steady_clock::now();}
#define ELAPSED std::chrono::duration<double, std::nano>(end - start).count()


//void set_selection_index(matrix_z &sel_ind, int n) {
//    sel_ind.setZero();
//    int nrow = sel_ind.rows();
//
//    for (int i = 0; i < nrow; ++i)
//        sel_ind(i, 0) = rand() % n;
//}

void test_cloud_client(int num_trial) {
    // m: decision node
    int n, m;
    NetAdapter* net = new NetAdapter(1);

    // secure input selection
    for (int i = 0; i < 5; ++i) {
        n = param_nd[i][0];
        m = pow(2, param_nd[i][1]) - 1;

        ss_tuple_mz sel_ind(m, 1); // I feature selection vector
        ss_tuple_mz x(n, 1); // feature vector

        set_selection_index(sel_ind.plain, n);

        sel_ind.encrypt();
        x.encrypt();

        mpz_class (*selected_feature)[2] = new mpz_class[m][2];
        double time_total = 0;
        for (int j = 0; j < num_trial; ++j) {
            CLOCK_START
            for (int k = 0; k < 1; k++)
                secure_feature_selection_with_one_node_client(x.share[1], sel_ind.share[1], selected_feature[k][1], k, net);
            CLOCK_END
            time_total += ELAPSED;

            cache_flusher();
        }

        printf("secure node selection (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m,
               time_total / num_trial / 2); // count only one party
//        delete[]selected_feature;

        std::cout  << "delete selected feature\n";
    }

    // secure node evaluation
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
//            ss_encrypt(gmp_prn.get_z_bits(CONFIG_L), x[j]);
//            ss_encrypt(gmp_prn.get_z_bits(CONFIG_L), y[j]);
        }

        double time_total = 0;
        for (int j = 0; j < num_trial; ++j) {
            CLOCK_START
            for (int k = 0; k < m; ++k)
                secure_node_eval_with_look_ahead_carry_adder_client(x[k], y[k], tri_z, tri_b, net);
            CLOCK_END
            time_total += ELAPSED;

            cache_flusher();
        }

        printf("secure node evaluation (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m,
               time_total / num_trial / 2); // count only one party

        delete[] x;
        delete[] y;
    }

    // secure inference generation
    int d;
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
        for (int j = 0; j < num_trial; ++j) {
            CLOCK_START
            secure_inference_generation_client(decision, value, d, result, tri_b, tri_z, net);
            CLOCK_END
            time_total += ELAPSED;

            cache_flusher();
        }

        printf("secure inference generation (n=%d, d=%d): %f ns\n", n, d, time_total / num_trial); // one party
        delete[] decision;
        delete[] value;
//        delete[] result;
    }

    net->close();
}

