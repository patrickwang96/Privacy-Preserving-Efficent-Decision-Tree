#ifndef TYPES_H
#define TYPES_H

#include "config.h"

#include <gmpxx.h>
#include <Eigen/Core>
#include <Eigen/Dense>

namespace Eigen {
  template<> struct NumTraits<mpz_class> : GenericNumTraits<mpz_class>
  {
    typedef mpz_class Real;
    typedef mpz_class NonInteger;
    typedef mpz_class Nested;
    static inline Real epsilon() { return 0; }
    static inline Real dummy_precision() { return 0; }
    //static inline Real digits10() { return 0; }
    enum {
      IsInteger = 1,
      IsSigned = 1,
      IsComplex = 0,
      RequireInitialization = 1,
      ReadCost = 1,
      AddCost = 1,
      MulCost = 1
    };
  };
}

typedef Eigen::Matrix<int, Eigen::Dynamic, Eigen::Dynamic> matrix_i;
typedef Eigen::Matrix<double, Eigen::Dynamic, Eigen::Dynamic> matrix_d;
typedef Eigen::Matrix<mpz_class, Eigen::Dynamic, Eigen::Dynamic> matrix_z;

// Triplet for beaver's secure multiplication protocol
typedef struct triplet_bit {
	triplet_bit();

	int u;
	int g;
	int z;

	int us[2];
	int gs[2];
	int zs[2];
} triplet_b;

typedef struct triplet_mpz {
	triplet_mpz();

	mpz_class u;
	mpz_class g;
	mpz_class z;

	mpz_class us[2];
	mpz_class gs[2];
	mpz_class zs[2];
} triplet_z;

typedef struct triplet_m {
	triplet_m();

	// matrix version
	triplet_m(int X_row, int X_col, int Y_col);

	// piecewise version
	explicit triplet_m(int n);

	matrix_z X;
	matrix_z Y;
	matrix_z Z;
} triplet_mz;

// Secret-sharing tuples used for convenient prototyping
typedef struct ss_tuple {
	// big three
	ss_tuple();
    ss_tuple(const ss_tuple& s);
	ss_tuple& operator= (const ss_tuple& rhs);

	ss_tuple(int nrow, int ncol);

	void encrypt();

	void decrypt();

    void reset();

	matrix_z plain;
	matrix_z share[2];
} ss_tuple_mz;

typedef struct tri_tuple {
	// big three
	tri_tuple();
	tri_tuple(const tri_tuple& t);
	tri_tuple& operator= (const tri_tuple& rhs);

	// matrix version
	tri_tuple(int X_row, int X_col, int Y_col);

	// piecewise version
	explicit tri_tuple(int n);

	void encrypt();

	void decrypt();

	triplet_mz plain;
	triplet_mz share[2];
} tri_tuple_mz;

#endif