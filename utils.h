#ifndef UTILS_H
#define UTILS_H

#include "types.h"

void cache_flusher();

void print_bits(mpz_class n);

void matrix_rand_2exp(matrix_z &mat, int l);

void rand_prime(mpz_class &rlt, int l);

int mod_pos(int x, int d);

int mod_bit(int x);

void mod_prime(mpz_class &x, const mpz_class &p);

void mod_2exp(mpz_class &x, int n);

void mod_2exp(matrix_z &mat, int n);

const int param_nd[5][2] = {{13, 3},
                            {15, 4},
                            {9,  8},
                            {13, 13},
                            {57, 17}};

#endif