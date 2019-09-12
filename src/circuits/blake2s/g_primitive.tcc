#ifndef __ZETH_G_PRIMITIVE_TCC__
#define __ZETH_G_PRIMITIVE_TCC__

namespace libzeth
{

template<typename FieldT>
g_primitive<FieldT>::g_primitive(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> a,
    libsnark::pb_variable_array<FieldT> b,
    libsnark::pb_variable_array<FieldT> c,
    libsnark::pb_variable_array<FieldT> d,
    libsnark::pb_variable_array<FieldT> x,
    libsnark::pb_variable_array<FieldT> y,
    libsnark::pb_variable_array<FieldT> a2,
    libsnark::pb_variable_array<FieldT> b2,
    libsnark::pb_variable_array<FieldT> c2,
    libsnark::pb_variable_array<FieldT> d2,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , a2(a2)
    , b2(b2)
    , c2(c2)
    , d2(d2)
{
    a1.allocate(pb, 32, "a1");
    b1.allocate(pb, 32, "b1");
    c1.allocate(pb, 32, "c1");
    d1.allocate(pb, 32, "d1");
    a1_temp.allocate(pb, 32, "a1_temp");
    a2_temp.allocate(pb, 32, "a2_temp");

    a1_1_gadget.reset(
        new double_bit32_sum_eq_gadget<FieldT>(pb, a, b, a1_temp));
    a1_2_gadget.reset(
        new double_bit32_sum_eq_gadget<FieldT>(pb, a1_temp, x, a1));
    d_xor_gadget.reset(new xor_rot_gadget<FieldT>(pb, d, a1, 16, d1));
    c1_gadget.reset(new double_bit32_sum_eq_gadget<FieldT>(pb, c, d1, c1));
    b_xor_gadget.reset(new xor_rot_gadget<FieldT>(pb, b, c1, 12, b1));

    a2_1_gadget.reset(
        new double_bit32_sum_eq_gadget<FieldT>(pb, a1, b1, a2_temp));
    a2_2_gadget.reset(
        new double_bit32_sum_eq_gadget<FieldT>(pb, a2_temp, y, a2));
    d1_xor_gadget.reset(new xor_rot_gadget<FieldT>(pb, d1, a2, 8, d2));
    c2_gadget.reset(new double_bit32_sum_eq_gadget<FieldT>(pb, c1, d2, c2));
    b1_xor_gadget.reset(new xor_rot_gadget<FieldT>(pb, b1, c2, 7, b2));
};

template<typename FieldT> void g_primitive<FieldT>::generate_r1cs_constraints()
{
    // 262 constraints (4 * 32 (xor) + 4 * 33 (add true) + 2 * 1 (add false))
    a1_1_gadget->generate_r1cs_constraints(
        false); // we do not check the booleaness of this temp variable
    a1_2_gadget->generate_r1cs_constraints();
    d_xor_gadget->generate_r1cs_constraints();

    c1_gadget->generate_r1cs_constraints();
    b_xor_gadget->generate_r1cs_constraints();

    a2_1_gadget->generate_r1cs_constraints(
        false); // we do not check the booleaness of this temp variable
    a2_2_gadget->generate_r1cs_constraints();
    d1_xor_gadget->generate_r1cs_constraints();
    c2_gadget->generate_r1cs_constraints();
    b1_xor_gadget->generate_r1cs_constraints();
};

template<typename FieldT> void g_primitive<FieldT>::generate_r1cs_witness()
{
    a1_1_gadget->generate_r1cs_witness();
    a1_2_gadget->generate_r1cs_witness();
    d_xor_gadget->generate_r1cs_witness();
    c1_gadget->generate_r1cs_witness();
    b_xor_gadget->generate_r1cs_witness();

    a2_1_gadget->generate_r1cs_witness();
    a2_2_gadget->generate_r1cs_witness();
    d1_xor_gadget->generate_r1cs_witness();
    c2_gadget->generate_r1cs_witness();
    b1_xor_gadget->generate_r1cs_witness();
};

} // namespace libzeth

#endif // __ZETH_G_PRIMITIVE_TCC__