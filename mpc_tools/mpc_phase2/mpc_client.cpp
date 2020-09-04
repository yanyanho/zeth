// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

// Utility for executing operations that are only required by "clients" (that
// is, participants in the MPC that only contribute and potentially validate
// the final transcript.

#include "libzeth/circuits/circuit_wrapper.hpp"
#include "mpc_common.hpp"

void zeth_protoboard(libsnark::protoboard<libzeth::FieldT> &pb)
{
    std::array<libzeth::FieldT, libzeth::ZETH_NUM_JS_INPUTS> roots;
    roots[0] = libzeth::FieldT("0");
    roots[1] = libzeth::FieldT("0");
    std::array<libzeth::joinsplit_input<libzeth::FieldT, libzeth::ZETH_MERKLE_TREE_DEPTH>, libzeth::ZETH_NUM_JS_INPUTS> inputs;
    std::array<libzeth::zeth_note, libzeth::ZETH_NUM_JS_OUTPUTS> outputs;
    libzeth::bits64 vpub_in = libzeth::bits64_from_hex("2F0000000000000F");
    libzeth::bits64 vpub_out = libzeth::bits64_from_hex("2F0000000000000F");
    libzeth::bits254 h_sig_in = libzeth::bits254_from_hex(
            "15b86771a6ac5a24fb0a9a4d369d00070f495685c1783bec6b2d21f5efa24eef");
    libzeth::bits254 phi_in = libzeth::bits254_from_hex(
            "15b86771a6ac5a24fb0a9a4d369d00070f495685c1783bec6b2d21f5efa24eef");
    libzeth::joinsplit_gadget<
        libzeth::FieldT,
        libzeth::HashT,
        libzeth::HashTreeT,
        libzeth::ZETH_NUM_JS_INPUTS,
        libzeth::ZETH_NUM_JS_OUTPUTS,
        libzeth::ZETH_MERKLE_TREE_DEPTH>
        js(pb, roots, inputs, outputs, vpub_in, vpub_out, h_sig_in, phi_in);
    js.generate_r1cs_constraints();
}

int main(int argc, char **argv)
{
    const std::map<std::string, subcommand *> commands{
        {"phase2-contribute", mpc_phase2_contribute_cmd},
        {"phase2-verify-transcript", mpc_phase2_verify_transcript_cmd},
        {"create-keypair", mpc_create_keypair_cmd},
    };
    return mpc_main(argc, argv, commands, zeth_protoboard);
}
