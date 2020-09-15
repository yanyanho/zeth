// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_PRFS_PRF_TCC__
#define __ZETH_CIRCUITS_PRFS_PRF_TCC__

#include "libzeth/circuits/prfs/prf.hpp"
#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/utils.hpp"
// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/prfs.tcc

namespace libzeth
{

template<typename FieldT, typename HashT>
PRF_gadget<FieldT, HashT>::PRF_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> &x,
    const libsnark::pb_variable_array<FieldT> &y,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), result(result)
{
        /*
    block.reset(new libsnark::block_variable<FieldT>(
        pb, {x, y}, FMT(this->annotation_prefix, " block")));

    hasher.reset(new HashT(
        pb, *block, *result, FMT(this->annotation_prefix, " hasher_gadget")));
         */
    reverse_x.allocate(pb, 254, "reverse_x");
    reverse_y.allocate(pb, 254, "reverse_y");
    left.allocate(pb, "left");
    right.allocate(pb, "right");
    for (int i = 0; i < 254; i++)
    {
        pb.val(reverse_x[i]) = pb.val(x[254-1-i]);
        pb.val(reverse_y[i]) = pb.val(y[254-1-i]);
    }
    this->pb.val(left) = reverse_x.get_field_element_from_bits(pb);
    std::cout << "left: " << std::endl;
    this->pb.val(left).print();
    this->pb.val(right) = reverse_y.get_field_element_from_bits(pb);
    std::cout << "right: " << std::endl;
    this->pb.val(right).print();
    hasher.reset(new HashT(
            pb, left, right, FMT(this->annotation_prefix, " hasher_gadget")));
}

template<typename FieldT, typename HashT>
void PRF_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    hasher->generate_r1cs_constraints();
    /*
    std::cout << "hash result: " << std::endl;
    this->pb.val(hasher->result()).print();
    libsnark::pb_variable<FieldT> re;
    this->pb.val(re) = result->bits.get_field_element_from_bits(this->pb);
    this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(1, re, hasher->result()),
            FMT(this->annotation_prefix, " lhs_rhs_equality_constraint"));
            */
}

template<typename FieldT, typename HashT>
void PRF_gadget<FieldT, HashT>::generate_r1cs_witness()
{
    hasher->generate_r1cs_witness();
    std::cout << "hash result: " << std::endl;
    this->pb.val(hasher->result()).print();
    std::cout << "hex: " << field_element_to_hex(this->pb.val(hasher->result())) << std::endl;
    result->generate_r1cs_witness(libff::bit_vector(
            bits254_to_vector(bits254_from_hex(field_element_to_hex(this->pb.val(hasher->result()))))));
}

template<typename FieldT, typename HashT>
libsnark::pb_variable_array<FieldT> gen_254_zeroes(
    const libsnark::pb_variable<FieldT> &ZERO)
{
    libsnark::pb_variable_array<FieldT> ret;
    // We generate half a block of zeroes
    while (ret.size() < HashT::get_digest_len()) {
        ret.emplace_back(ZERO);
    }

    // Check that we correctly built a 256-bit (half a block) string since we
    // use blake2sCompress 256
    assert(ret.size() == 254);

    return ret;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_addr(
        libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk)
{
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ZERO);  // 0
    tagged_a_sk.emplace_back(ZERO);  // 00
    tagged_a_sk.emplace_back(ONE); // 001
    tagged_a_sk.emplace_back(ZERO); // 0010

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 250);
    for (size_t i = 0; i < 250; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 254-bit string
    assert(tagged_a_sk.size() == 254);
    std::cout << "PRF_addr_a_pk_gadget inputs: " << std::endl;
    tagged_a_sk.get_field_element_from_bits(pb).print();
    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_nf(
        libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk)
{
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ONE);  // 1
    tagged_a_sk.emplace_back(ZERO);  // 10
    tagged_a_sk.emplace_back(ONE);  // 101
    tagged_a_sk.emplace_back(ZERO); // 1010

    // Should always be satisfied because a_sk
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 250);
    for (size_t i = 0; i < 250; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 254-bit string
    assert(tagged_a_sk.size() == 254);
    std::cout << "PRF_nf_gadget inputs: " << std::endl;
    tagged_a_sk.get_field_element_from_bits(pb).print();
    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_pk(
        libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    size_t index)
{
    libsnark::pb_variable_array<FieldT> tagged_a_sk;
    tagged_a_sk.emplace_back(ZERO); // 0

    // Index should either be 0 or 1 since we support
    // joinsplit with 2 inputs only
    if (index == 0) {                   // 0 || index
        tagged_a_sk.emplace_back(ZERO); // 00
    } else {
        tagged_a_sk.emplace_back(ONE); // 01
    }

    tagged_a_sk.emplace_back(ZERO); // 0 || index || 0
    tagged_a_sk.emplace_back(ZERO); // 0 || index || 00

    // Should always be satisfied because a_sk
    // is a 254 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the a_sk vector
    assert(a_sk.size() > 250);
    for (size_t i = 0; i < 250; ++i) {
        tagged_a_sk.emplace_back(a_sk[i]);
    }

    // Check that we correctly built a 254-bit string
    assert(tagged_a_sk.size() == 254);
    std::cout << "PRF_pk_gadget inputs: " << std::endl;
    tagged_a_sk.get_field_element_from_bits(pb).print();
    return tagged_a_sk;
}

template<typename FieldT>
libsnark::pb_variable_array<FieldT> get_tag_rho(
        libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &phi,
    size_t index)
{
    libsnark::pb_variable_array<FieldT> tagged_phi;
    tagged_phi.emplace_back(ZERO); // 0

    if (index == 0) {                  // 0 || index
        tagged_phi.emplace_back(ZERO); // 00
    } else {
        tagged_phi.emplace_back(ONE); // 01
    }

    tagged_phi.emplace_back(ONE);  // 0 || index || 1
    tagged_phi.emplace_back(ZERO); // 0 || index || 10

    // Should always be satisfied because phi
    // is a 256 bit string. This is just a sanity check
    // to make sure that the for loop doesn't
    // go out of the bound of the phi vector
    assert(phi.size() > 250);
    for (size_t i = 0; i < 250; ++i) {
        tagged_phi.emplace_back(phi[i]);
    }

    // Check that we correctly built a 256-bit string
    assert(tagged_phi.size() == 254);
    std::cout << "PRF_rho_gadget inputs: " << std::endl;
    tagged_phi.get_field_element_from_bits(pb).print();
    return tagged_phi;
}

// PRF to generate the public addresses
// a_pk = blake2sCompress(0010 || [a_sk]_250 || 0^256): See ZCash protocol
// specification paper, page 57
template<typename FieldT, typename HashT>
PRF_addr_a_pk_gadget<FieldT, HashT>::PRF_addr_a_pk_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : PRF_gadget<FieldT, HashT>(
          pb,
          get_tag_addr(pb, ZERO, a_sk),
          gen_254_zeroes<FieldT, HashT>(ZERO),
          result,
          annotation_prefix)
{
    // Nothing
}

// PRF to generate the nullifier
// nf = blake2sCompress(1010 || [a_sk]_250 || rho): See ZCash protocol
// specification paper, page 57
template<typename FieldT, typename HashT>
PRF_nf_gadget<FieldT, HashT>::PRF_nf_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    const libsnark::pb_variable_array<FieldT> &rho,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : PRF_gadget<FieldT, HashT>(
          pb, get_tag_nf(pb, ZERO, a_sk), rho, result, annotation_prefix)
{
    // Nothing
}

// PRF to generate the h_i
// h_i = blake2sCompress(0 || i || 00 || [a_sk]_252 || h_sig): See ZCash
// protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_pk_gadget<FieldT, HashT>::PRF_pk_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &a_sk,
    const libsnark::pb_variable_array<FieldT> &h_sig,
    size_t index,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : PRF_gadget<FieldT, HashT>(
          pb, get_tag_pk(pb, ZERO, a_sk, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

// PRF to generate rho
// rho_i = blake2sCompress(0 || i || 10 || [a_sk]_252 || h_sig): See ZCash
// protocol specification paper, page 57
template<typename FieldT, typename HashT>
PRF_rho_gadget<FieldT, HashT>::PRF_rho_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    const libsnark::pb_variable_array<FieldT> &phi,
    const libsnark::pb_variable_array<FieldT> &h_sig,
    size_t index,
    std::shared_ptr<libsnark::digest_variable<FieldT>> result,
    const std::string &annotation_prefix)
    : PRF_gadget<FieldT, HashT>(
          pb, get_tag_rho(pb, ZERO, phi, index), h_sig, result, annotation_prefix)
{
    // Nothing
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_PRFS_PRF_TCC__
