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

#endif