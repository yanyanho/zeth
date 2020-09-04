// Copyright (c) 2019 HarryR
// License: LGPL-3.0+
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/poseidon/poseidon.hpp"

#include "gtest/gtest.h"

using namespace libzeth;

typedef libzeth::ppT ppT;
typedef libff::Fr<ppT> FieldT;

/*
int main( int argc, char **argv )
{
    ppT::init_public_params();

    if( ! test_constants() )
        return 1;

    if( ! test_prove_verify() )
        return 2;

    const auto actual = Poseidon128<2,1>::permute({1, 2});
    const FieldT expected("12242166908188651009877250812424843524687801523336557272219921456462821518061");
    if( actual[0] != expected ) {
        cerr << "poseidon([1,2]) incorrect result, got ";
        actual[0].print();
    }

    std::cout << "OK" << std::endl;
    return 0;
}
*/
namespace
{
    TEST(TestPoseidon, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable_array<FieldT> x;
    x.allocate(pb, 2, "x");

    pb.val(x[0]) = FieldT("1");
    pb.val(x[1]) = FieldT("2");
    // Public input
    pb.set_input_sizes(1);

    Poseidon128<2,1,FieldT> the_gadget(pb, x[0], x[1], "gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("12242166908188651009877250812424843524687801523336557272219921456462821518061");
    ASSERT_TRUE(expected_out == pb.val(the_gadget.result()));
}
}
int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}