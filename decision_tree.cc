#include "decision_tree.h"
#include "secret_sharing.h"

#include "utils.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <math.h>
#include <mutex>
#include <thread>
#include <vector>

extern gmp_randclass gmp_prn;

#define SS_DO(expr) \
    for(int i=0; i<2; ++i) {expr}

inline int bit(mpz_class n, int k) 
{
    return n.get_ui() >> k & 1;
}

	
// secure computation protocols
void secure_multiplication(const matrix_z shareA[2], const matrix_z shareB[2], 
                          const triplet_mz shareTri[2],
                          // intermediate buffers
                          ss_tuple_mz &U, ss_tuple_mz &V, 
                          // output
                          matrix_z shareAB[2],
                          // whether to conduct piecewise multiplication
                          int piecewise)
{
    // 1)
    for(int i=0; i<2; ++i) {
        U.share[i] = shareA[i] - shareTri[i].X;
        V.share[i] = shareB[i] - shareTri[i].Y;
    }

    // 2)
    U.decrypt();
    V.decrypt();

    // 3)
    for(int i=0; i<2; ++i) {
        if(piecewise) {
            if(i==1)
                shareAB[i].array() += U.plain.array()*V.plain.array();
            shareAB[i].array() += U.plain.array()*shareTri[i].Y.array();
            shareAB[i].array() += shareTri[i].X.array()*V.plain.array();
        }
        else {
            if(i==1)
                shareAB[i] += U.plain*V.plain;
            shareAB[i] += U.plain*shareTri[i].Y;
            shareAB[i] += shareTri[i].X*V.plain;
        }
        shareAB[i] += shareTri[i].Z;
    }

    mod_2exp(shareAB[0], CONFIG_L);
    mod_2exp(shareAB[1], CONFIG_L);
}

void secure_mul(int as[2], int bs[2], int ab_s[2], const triplet_b& tri)
{
    int e, es[2], f, fs[2];
    SS_DO(es[i] = mod_bit(as[i] - tri.us[i]);
          fs[i] = mod_bit(bs[i] - tri.gs[i]);)

    ss_decrypt(e, es);
    ss_decrypt(f, fs);

    SS_DO(ab_s[i] = mod_bit(i*e*f + e*tri.gs[i] + f*tri.us[i] + tri.zs[i]);)
}

void secure_mul(mpz_class as[2], mpz_class bs[2], mpz_class ab_s[2], const triplet_z& tri)
{
    mpz_class e, es[2], f, fs[2];
    SS_DO(es[i] = as[i] - tri.us[i];
          mod_2exp(es[i], CONFIG_L);
          fs[i] = bs[i] - tri.gs[i];
          mod_2exp(fs[i], CONFIG_L);)

    ss_decrypt(e, es);
    ss_decrypt(f, fs);

    SS_DO(ab_s[i] = i*e*f + e*tri.gs[i] + f*tri.us[i] + tri.zs[i];
          mod_2exp(ab_s[i], CONFIG_L);)
}

void secure_node_evaluation(mpz_class x[2], mpz_class y[2], const triplet_z& tri_z, const triplet_b& tri_b)
{
    mpz_class a[2];

    SS_DO(a[i] = y[i] - x[i];
          mod_2exp(a[i], CONFIG_L);)

    // set 1st bit
    int p[2] = {bit(a[0], 0), 0};
    int q[2] = {0, bit(a[1], 0)};
    int c[2], d[2], e[2];
    secure_mul(p, q, c, tri_b);

    // set the 2nd bit for w, p and q
    int w[2] = {bit(a[0], 1), bit(a[1], 1)};
    p[0] = bit(a[0], 1);
    q[1] = bit(a[1], 1);

    // step through all remaining bits
    for(int i=1; i<CONFIG_L; ++i) {
        // step a)
        secure_mul(p, q, d, tri_b);
        d[1] = mod_bit(d[1]+1);
        // step b)
        secure_mul(w, c, e, tri_b);
        e[1] = mod_bit(e[1]+1);
        // step c) note that c is updated here and used in next iteration
        // skip the final iteration to retain its (l-1)th value
        if(i < (CONFIG_L-1)) {
            secure_mul(e, d, c, tri_b);
            c[1] = mod_bit(c[1]+1);
        }

        // prepare w, p and q for next bit
        w[0] = bit(a[0], i);
        w[1] = bit(a[1], i);
        p[0] = bit(a[0], i);
        q[1] = bit(a[1], i);
    }

    // extract MSB
    int al[2];
    // secure_mul(w, c, al, tri_b); historic error
    SS_DO(al[i] = w[i] + c[i];)

    // int alv;
    // ss_decrypt(alv, al);
    //std::cout << "before conversion " << vx << " < " << vy << " is " << (alv?"true":"false") << std::endl;

    // conversion from Z_2 to Z_p
    mpz_class t1[2] = {al[0], 0}, t2[2] = {0, al[1]};
    mpz_class t1t2[2];
    secure_mul(t1, t2, t1t2, tri_z);

    mpz_class bs[2];
    SS_DO(bs[i] = t1[i]+t2[i]-2*t1t2[i];
          // for polynomial
          mod_2exp(bs[i], CONFIG_L);) 
          // for path cost, no difference in performance as CONFIG_P has CONFIG_L bits
          //mod_prime(bs[i], CONFIG_P);)

    // mpz_class b;
    // ss_decrypt(b, bs);

    // mpz_class vx, vy;
    // ss_decrypt(vx, x);
    // ss_decrypt(vy, y);

    // std::cout << "b is " << b << std::endl;
    // std::cout << "after conversion " << vx << " < " << vy << " is " << (b?"true":"false") << std::endl;
}

void secure_class_generation_path_cost(const std::vector<mpz_class>& edges, std::vector<mpz_class>& leaf_value, std::vector<mpz_class>& interm_rlt, std::vector<mpz_class>& path_cost, int depth)
{
    /*  complete traversal of the binary tree
                  0                 
            1            2          depth=1
          3   4       5     6       depth=2
         7 8 9 10   11 12 13 14     depth=3
        ...      ...         ...    depth=4 (leaves)

        egde_id goes with node_id
    */

    int first_leaf = pow(2, depth) - 1;
    int num_leaf = pow(2, depth);

    // non-leaf nodes
    int id = 0;
    for(id=1; id < first_leaf; ++id)
        interm_rlt[id] += interm_rlt[(id-1)/2] + edges[id];

    // leaf nodes
    for(int i=0; i < num_leaf; ++i, ++id)
        path_cost[i] = interm_rlt[(id-1)/2] + edges[id];

    /* masking */
    for(int i=0; i<num_leaf; ++i) {
        leaf_value[i] += gmp_prn.get_z_range(CONFIG_P)*path_cost[i];
        mod_prime(leaf_value[i], CONFIG_P);

        path_cost[i] *= gmp_prn.get_z_range(CONFIG_P);
        mod_prime(path_cost[i], CONFIG_P);
    }

    // permutation
    std::random_shuffle(path_cost.begin(), path_cost.end());
    std::random_shuffle(leaf_value.begin(), leaf_value.end());
}

void secure_class_generation_polynomial(mpz_class (*edges)[2], mpz_class (*leaf_value)[2], mpz_class (*interm_rlt)[2], mpz_class (*path_mul)[2], const triplet_z& tri, int depth)
{
    // complete traversal of the binary tree
    //             0                 
    //       1            2          depth=1
    //     3   4       5     6       depth=2
    //    7 8 9 10   11 12 13 14     depth=3
    //   ...      ...         ...    depth=4 (leaves)

    //   egde_id goes with node_id

    int first_leaf = pow(2, depth) - 1;
    int num_leaf = pow(2, depth);

    // non-leaf nodes
    int id = 0;
    interm_rlt[0][0] = edges[0][0];
    interm_rlt[0][1] = edges[0][1];
    for(id=1; id < first_leaf; ++id)
        secure_mul(interm_rlt[(id-1)/2], edges[id], interm_rlt[id], tri);

    // leaf nodes
    for(int i=0; i < num_leaf; ++i, ++id) {
        secure_mul(interm_rlt[(id-1)/2], edges[id], path_mul[i], tri);
    }

    mpz_class final[2];
    // final value
    for(int i=0; i < num_leaf; ++i) {
        secure_mul(path_mul[i], leaf_value[i], leaf_value[i], tri);

        final[0] += leaf_value[i][0];
        final[1] += leaf_value[i][1];
    }
}