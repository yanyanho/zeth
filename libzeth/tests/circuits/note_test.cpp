// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/circuits/notes/note.hpp"
#include "libzeth/core/bits.hpp"
#include "libzeth/core/merkle_tree_field.hpp"
#include "libzeth/core/note.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/circuits/poseidon/poseidon.hpp"
#include "libzeth/core/field_element_utils.hpp"
#include <gtest/gtest.h>

using namespace libzeth;

typedef libzeth::ppT ppT;

// Should be alt_bn128 in the CMakeLists.txt
typedef libff::Fr<ppT> FieldT;

// We use our hash functions to do the tests
//typedef BLAKE2s_256<FieldT> HashT;
typedef Poseidon128<2,1,FieldT> HashT;
typedef Poseidon128<2,1,FieldT> HashTreeT;
static const size_t TreeDepth = 5;

namespace
{

TEST(TestNoteCircuits, TestInputNoteGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();
    libff::enter_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);
    bits254 trap_r_bits254 = bits254_from_hex(
        "15b86771a6ac5a24fb0a9a4d369d00070f495685c1783bec6b2d21f5efa24eef");
    /*
    libsnark::pb_variable_array<FieldT> bits;
    bits.allocate(pb, 254, " bits");
    bits254 nullf_bits254 = bits254_from_hex("04af993ecafdd81074ba167887039ca53ae73fa9df553f421c395022aa384ab8");
    bits.fill_with_bits(libff::bit_vector(bits254_to_vector(nullf_bits254)));
    std::cout << "convert_bits" << std::endl;
    bits.get_field_element_from_bits(pb).print();
     */
    bits64 value_bits64 = bits64_from_hex("2F0000000000000F");
    bits254 a_sk_bits254 = bits254_from_hex(
        "1388157cc25efd1d8e0cce226a1d553d98f331798f5b1744518d21f5efa24e6b");
    bits254 rho_bits254 = bits254_from_hex(
        "13826c9424e9d7f9471a21d59f5faf1483572c5402e953ec6b2d21f5efa24e6b");
    // Get a_pk from a_sk (PRF)
    //
    // 1100 || [a_sk]_252 =
    // 0xCFF0000000000000000000000000000000000000000000000000000000000000
    // 0^256 =
    // 0x0000000000000000000000000000000000000000000000000000000000000000
    // a_pk = blake2s( 1100 || [a_sk]_252 || 0^256)
    // Generated directly from a_sk and hashlib blake2s
    bits254 a_pk_bits254 = bits254_from_hex(
        "1388157cc25efd1d8e057f32fa7c750275614659a0fa1dec6b2d21f5efa24e6b");
    // Get nf from a_sk and rho (PRF)
    //
    // nf = blake2s( 1110 || [a_sk]_252 || rho)
    // 1110 || [a_sk]_252 =
    // 0xEFF0000000000000000000000000000000000000000000000000000000000000
    // rho = FFFF000000000000000000000000000000000000000000000000000000009009
    // The test vector generated directly from a_sk and hashlib blake2s, gives:
    bits254 nf_bits254 = bits254_from_hex(
        "13826c9424e9d785471a21d59f5faf1483572c5402e953ec6b2d21f5efa24e6b");
    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    // Converted from old hex string
    // "e672300b3f422966e7cf8ea77e38ef0da595f3933eaf2d698a9859eb3bf674aa"
    // (big-endian)
    FieldT cm_field = FieldT("6330279160344623720478567627080216273711033746324460058478654282586865606858");

    libff::leave_block(
        "Initialize the coins' data (nullifier, a_sk and a_pk, cm, rho)", true);

    libff::enter_block(
        "Setup a local merkle tree and append our commitment to it", true);
    std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>> test_merkle_tree =
        std::unique_ptr<merkle_tree_field<FieldT, HashTreeT>>(
            new merkle_tree_field<FieldT, HashTreeT>(TreeDepth));

    // In practice the address is emitted by the mixer contract once the
    // commitment is appended to the tree
    const size_t address_commitment = 1;
    libff::bit_vector address_bits;
    for (size_t i = 0; i < TreeDepth; ++i) {
        address_bits.push_back((address_commitment >> i) & 0x1);
        std::cout << "address_bits" << address_bits[i] << std::endl;
    }
    test_merkle_tree->set_value(address_commitment, cm_field);

    // Get the root of the new/non-empty tree (after insertion)
    FieldT updated_root_value = test_merkle_tree->get_root();

    std::cout << "updated_root_value" << std::endl;
    updated_root_value.print();

    libff::leave_block(
        "Setup a local merkle tree and append our commitment to it", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);

    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_digest;
    a_sk_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "a_sk_digest"));
    a_sk_digest->generate_r1cs_constraints();
    a_sk_digest->generate_r1cs_witness(
        libff::bit_vector(bits254_to_vector(a_sk_bits254)));

    std::shared_ptr<libsnark::digest_variable<FieldT>> rho_digest;
    rho_digest.reset(new libsnark::digest_variable<FieldT>(
            pb, HashT::get_digest_len(), "rho_digest"));
    rho_digest->generate_r1cs_constraints();
    rho_digest->generate_r1cs_witness(
    libff::bit_vector(bits254_to_vector(rho_bits254)));

    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier_digest;
    nullifier_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "nullifier_digest"));
    nullifier_digest->generate_r1cs_constraints();
    nullifier_digest->generate_r1cs_witness(
        libff::bit_vector(bits254_to_vector(nf_bits254)));
    /*
    std::shared_ptr<libsnark::pb_variable<FieldT>> merkle_root;
    merkle_root.reset(new libsnark::pb_variable<FieldT>);
    (*merkle_root).allocate(pb, "root");
    pb.val(*merkle_root) = updated_root_value;
    */
    libsnark::pb_variable<FieldT> merkle_root;
    merkle_root.allocate(pb, "root");
    pb.val(merkle_root) = updated_root_value;
    // Create a note from the coin's data
    zeth_note note(a_pk_bits254, value_bits64, rho_bits254, trap_r_bits254);

    std::shared_ptr<input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>>
        input_note_g = std::shared_ptr<
            input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>>(
            new input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
                pb, ZERO, a_sk_digest, nullifier_digest, rho_digest, merkle_root, note));

    // Get the merkle path to the commitment we appended
    std::vector<FieldT> path = test_merkle_tree->get_path(address_commitment);
    for (size_t i = 0; i < path.size(); ++i)
    {
        std::cout << "path" << std::endl;
        path[i].print();
    }


    input_note_g->generate_r1cs_constraints();
    input_note_g->generate_r1cs_witness(path, address_bits, note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;

    ASSERT_TRUE(is_valid_witness);
};

TEST(TestNoteCircuits, TestOutputNoteGadget)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libff::enter_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);
    bits254 trap_r_bits254 = bits254_from_hex(
        "15b86771a6ac5a24fb0a9a4d369d00070f495685c1783bec6b2d21f5efa24eef");
    bits64 value_bits64 = bits64_from_hex("2F0000000000000F");
    bits254 rho_bits254 = bits254_from_hex(
        "13826c9424e9d7f9471a21d59f5faf1483572c5402e953ec6b2d21f5efa24e6b");
    bits254 a_pk_bits254 = bits254_from_hex(
        "1388157cc25efd1d8e057f32fa7c750275614659a0fa1dec6b2d21f5efa24e6b");

    // Get the coin's commitment (COMM)
    //
    // cm = blake2s(r || a_pk || rho || value_v)
    FieldT cm = FieldT("7523924190484737417062491405979066097719677953530653401413292929429080200051");
    libff::leave_block(
        "Initialize the output coins' data (a_pk, cm, rho)", true);

    libff::enter_block(
        "Data conversion to generate a witness of the note gadget", true);
    std::shared_ptr<libsnark::digest_variable<FieldT>> rho_digest;
    rho_digest.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), "rho_digest"));
    rho_digest->generate_r1cs_constraints();
    rho_digest->generate_r1cs_witness(
        libff::bit_vector(bits254_to_vector(rho_bits254)));

    libsnark::pb_variable<FieldT> commitment;
    commitment.allocate(pb, " commitment");

    // Create a note from the coin's data
    zeth_note note(a_pk_bits254, value_bits64, rho_bits254, trap_r_bits254);
    std::shared_ptr<output_note_gadget<FieldT, HashT>> output_note_g =
        std::shared_ptr<output_note_gadget<FieldT, HashT>>(
            new output_note_gadget<FieldT, HashT>(pb, rho_digest, commitment, note));
    std::cout << "here" << std::endl;


    output_note_g->generate_r1cs_constraints();
    output_note_g->generate_r1cs_witness(note);
    libff::leave_block(
        "Data conversion to generate a witness of the note gadget", true);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "************* SAT result: " << is_valid_witness
              << " ******************" << std::endl;
    ASSERT_TRUE(is_valid_witness);

    // Last check to make sure the commitment computed is the expected one
    ASSERT_EQ(pb.val(commitment), cm);
};

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
