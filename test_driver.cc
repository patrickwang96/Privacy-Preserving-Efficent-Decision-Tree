// #include "test_driver.h"

#include "secret_sharing.h"
#include "utils.h"
#include "decision_tree.h"

#include <chrono>
#include <math.h>
#include <vector>

extern gmp_randclass gmp_prn;


auto start = std::chrono::steady_clock::now(), end = std::chrono::steady_clock::now();
#define CLOCK_START {start = std::chrono::steady_clock::now();}
#define CLOCK_END {end = std::chrono::steady_clock::now();}
#define ELAPSED std::chrono::duration<double, std::nano>(end - start).count()

void test_client(int num_trial)
{
	int n=0, m=0; 

	// feature vector encryption
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		m = pow(2, param_nd[i][1]) - 1;
		ss_tuple_mz feature(n,1);

		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			CLOCK_START
			feature.encrypt();
			CLOCK_END
			time_total += ELAPSED;

			feature.reset();
			cache_flusher();
		}

		printf("feature vector encryption (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m, time_total/num_trial);
	}


	// get final class result
	double time_total = 0;
	mpz_class final, final_share[2];
	for(int j=0; j<(num_trial*500); ++j) {
		ss_encrypt(gmp_prn.get_z_bits(CONFIG_L), final_share);

		CLOCK_START
		ss_decrypt(final, final_share);
		CLOCK_END
		time_total += ELAPSED;

		cache_flusher();
	}

	printf("final result generation : %f ns\n", time_total/num_trial/500);
}

void set_selection_index(matrix_z& sel_ind, int n)
{
	sel_ind.setZero();
	int nrow = sel_ind.rows();

	for(int i=0; i<nrow; ++i)
		sel_ind(i, 0) = rand() % n;
}

void test_sp(int num_trial)
{
	int n=0, m=0;
	
	// node threshold encryption
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		m = pow(2, param_nd[i][1]) - 1;
		ss_tuple_mz node(m,1);
		ss_tuple_mz prediction_value(m+1, 1);

		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			CLOCK_START
			node.encrypt();
			prediction_value.encrypt();
			CLOCK_END
			time_total += ELAPSED;

			node.reset();
			prediction_value.reset();
			cache_flusher();
		}

		printf("node encryption (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m, time_total/num_trial);
	}

	// selection index encryption
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		m = pow(2, param_nd[i][1]) - 1;
		ss_tuple_mz sel_ind(m, 1);

		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			set_selection_index(sel_ind.plain, n);

			CLOCK_START
			sel_ind.encrypt();
			CLOCK_END
			time_total += ELAPSED;

			sel_ind.reset();
			cache_flusher();
		}

		printf("selection index encryption (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m, time_total/num_trial);
	}
}

void test_cloud(int num_trial)
{
	// m: decision node
	int n, m;

	// secure input selection
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		m = pow(2, param_nd[i][1]) - 1;

		ss_tuple_mz  sel_ind(m, 1); // I feature selection vector
		ss_tuple_mz x(n, 1); // feature vector

        set_selection_index(sel_ind.plain, n);

        sel_ind.encrypt();
        x.encrypt();

        mpz_class (*selected_feature)[2] = new mpz_class [m][2];
		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			CLOCK_START
			for (int k = 0; k < m; k++)
                secure_feature_selection_with_one_node(x.share, sel_ind.share,selected_feature[k], k);
			CLOCK_END
			time_total += ELAPSED;

			cache_flusher();
		}

		printf("secure node selection (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m, time_total/num_trial/2); // count only one party
		delete []selected_feature;
	}

	// secure node evaluation
	triplet_b tri_b;
	triplet_z tri_z;
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		m = pow(2, param_nd[i][1]) - 1;

		// ugly staff for preparation
		mpz_class (*x)[2] = new mpz_class [m][2], (*y)[2] = new mpz_class [m][2];
		for(int j=0; j<m; ++j) {
			ss_encrypt(gmp_prn.get_z_bits(CONFIG_L), x[j]);
			ss_encrypt(gmp_prn.get_z_bits(CONFIG_L), y[j]);
		}

		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			CLOCK_START
			for(int k=0; k<m; ++k)
                secure_node_eval_with_look_ahead_carry_adder(x[k], y[k], tri_z, tri_b);
			CLOCK_END
			time_total += ELAPSED;

			cache_flusher();
		}

		printf("secure node evaluation (n=%d, d=%d, m=%d): %f ns\n", n, param_nd[i][1], m, time_total/num_trial/2); // count only one party

		delete[] x;
		delete[] y;
	}

	// secure inference generation
	int d;
	for(int i=0; i<5; ++i)
	{
		n = param_nd[i][0];
		d = param_nd[i][1];

		int num_of_edge = (1 << d) -1;
		int num_of_leaf = num_of_edge + 1;

		auto decision = new int[num_of_edge][2];
		auto value = new mpz_class[num_of_leaf][2];
		auto result = new mpz_class[2];

		double time_total = 0;
		for(int j=0; j<num_trial; ++j) {
			CLOCK_START
            secure_inference_generation(decision, value, d, result, tri_b, tri_z);
			CLOCK_END
			time_total += ELAPSED;

			cache_flusher();
		}

		printf("secure inference generation (n=%d, d=%d): %f ns\n", n, d, time_total/num_trial); // one party
		delete [] decision;
		delete [] value;
		delete [] result;
	}

}
