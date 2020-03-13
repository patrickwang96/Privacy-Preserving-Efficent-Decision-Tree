#include "utils.h"

#include <assert.h>
#include <stdio.h>

// c++ interface
gmp_randclass gmp_prn(gmp_randinit_default);

void cache_flusher()
{
	// 8MB L3 cache
	static const int l3_size = 1024*1024*8;
	static const int num_gar = l3_size / sizeof(int);
	static int garbage[num_gar];

	for(int i=0; i<num_gar; ++i)
		garbage[i] = rand();
}

void matrix_rand_2exp(matrix_z &mat, int l)
{	 
	mpz_class *data = mat.data();
	for (int i = 0, size = mat.size(); i < size; ++i)
		*(data + i) = gmp_prn.get_z_bits(l);				
}

void rand_prime(mpz_class &rlt, int l)
{
    rlt = gmp_prn.get_z_bits(l);
    while(mpz_probab_prime_p(rlt.get_mpz_t(), 15) != 2) {
        rlt = gmp_prn.get_z_bits(l);
    }
}

int mod_pos(int x, int d)
{
    // if(d < 0)
    //     exit(0);
    int r = x%d;
    if(r < 0)
        return r+d;
    else
        return r;
}

int mod_bit(int x)
{
	return mod_pos(x, 2);
}

void mod_prime(mpz_class &x, const mpz_class &p)
{
    mpz_fdiv_r(x.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
}

void mod_2exp(mpz_class &x, int n)
{
	mpz_fdiv_r_2exp(x.get_mpz_t(), x.get_mpz_t(), n);
}

void mod_2exp(matrix_z &mat, int n)
{
	mpz_class *data = mat.data();
	for (int i = 0, size = mat.size(); i<size; ++i) {
		mod_2exp(*(data + i), n);
	}
}