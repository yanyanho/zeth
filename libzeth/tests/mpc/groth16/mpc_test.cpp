// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/sha256/sha256_ethereum.hpp"
#include "libzeth/core/chacha_rng.hpp"
#include "libzeth/core/evaluator_from_lagrange.hpp"
#include "libzeth/core/multi_exp.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/mpc/groth16/mpc_utils.hpp"
#include "libzeth/mpc/groth16/phase2.hpp"
#include "libzeth/mpc/groth16/powersoftau_utils.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"
#include "libzeth/tests/circuits/simple_test.hpp"

#include <fstream>
#include <gtest/gtest.h>
#include <thread>

using namespace libzeth;
using namespace libsnark;

using PP = srs_pot_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

namespace
{

static r1cs_constraint_system<Fr> get_simple_constraint_system()
{
    protoboard<Fr> pb;
    libzeth::test::simple_circuit<Fr>(pb);
    r1cs_constraint_system<Fr> cs = pb.get_constraint_system();
    cs.swap_AB_if_beneficial();
    return cs;
}

// (Deterministic) creation of accumulator
template<typename ppT>
static srs_mpc_phase2_accumulator<ppT> dummy_initial_accumulator(
    libff::Fr<ppT> seed, size_t degree, size_t num_L_elements)
{
    // Dummy cs_hash from the seed.
    mpc_hash_t cs_hash;
    mpc_hash_ostream ss;
    ss << seed;
    ss.get_hash(cs_hash);

    libff::G1_vector<ppT> H_g1(degree - 1);
    for (libff::G1<ppT> &h : H_g1) {
        h = seed * libff::G1<ppT>::one();
        seed = seed + libff::Fr<ppT>::one();
    };

    libff::G1_vector<ppT> L_g1(num_L_elements);
    for (libff::G1<ppT> &l : L_g1) {
        l = seed * libff::G1<ppT>::one();
        seed = seed + libff::Fr<ppT>::one();
    };

    return srs_mpc_phase2_accumulator<ppT>(
        cs_hash,
        libff::G1<ppT>::one(),
        libff::G2<ppT>::one(),
        std::move(H_g1),
        std::move(L_g1));
}

TEST(MPCTests, HashToG2)
{
    mpc_hash_t hash;
    const std::string seed = hex_to_bytes(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    memcpy(hash, seed.data(), sizeof(mpc_hash_t));

    Fr expect_fr;
    {
        std::istringstream ss(
            hex_to_bytes("20e70f3b594e4a9bd78e7d23f796f3bce4de"
                         "92af13adf10beffe2cf84b59e2ad"));
        read_powersoftau_fr(ss, expect_fr);
    }

    G2 expect_g2;
    {
        std::istringstream ss(hex_to_bytes(
            "04048fb80ba85a814f6ca7db7194da6c71fa7d8b7aa05b49ce315c96c20b916ab"
            "36544a6656acae3f5a7da00ca96dfe5b9c4bcec736f75cf85a27fab44f426df28"
            "0532af644ab533ca189739ae2d908b95d643051f6692286eca126ad4c65275def"
            "8e0f6b24ebb57b415e59b465dc7f3f823c615434955b96f7f3f5ba4f7505e43"));
        read_powersoftau_g2(ss, expect_g2);
    }

    Fr fr;
    srs_mpc_digest_to_fp(hash, fr);
    G2 g2 = srs_mpc_digest_to_g2<ppT>(hash);

    ASSERT_EQ(expect_fr, fr);
    ASSERT_EQ(expect_g2, g2);
}

TEST(MPCTests, LinearCombination)
{
    // Compute the small test qap first, in order to extract the
    // degree.
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);

    // dummy powersoftau
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());

    // linear combination
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    // Checks that can be performed without knowledge of tau. (ratio
    // of terms in [ t(x) . x^i ]_1, etc).
    const size_t qap_n = qap.degree();
    ASSERT_EQ(qap_n, layer1.degree());
    ASSERT_EQ(qap_n - 1, layer1.T_tau_powers_g1.size());
    ASSERT_EQ(qap.num_variables() + 1, layer1.ABC_g1.size());

    for (size_t i = 1; i < qap_n - 1; ++i) {
        ASSERT_TRUE(::same_ratio<ppT>(
            layer1.T_tau_powers_g1[i - 1],
            layer1.T_tau_powers_g1[i],
            pot.tau_powers_g2[0],
            pot.tau_powers_g2[1]))
            << "i = " << std::to_string(i);
    }

    // Use knowledge of secrets to confirm values.
    // Check that:
    //
    //   [ domain.Z(tau) ]_1 = layer1.T_tau_powers_g1[0]
    //   [ beta . A_i(tau) + alpha . B_i(tau) + C_i(tau) ]_1 =
    //     layer1.ABC_g1[i]
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            constraint_system.swap_AB_if_beneficial();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau, true);
        })();

        ASSERT_EQ(
            qap_evaluation.domain->compute_vanishing_polynomial(tau) *
                G1::one(),
            layer1.T_tau_powers_g1[0]);

        for (size_t i = 0; i < qap_evaluation.num_variables() + 1; ++i) {
            // At
            ASSERT_EQ(qap_evaluation.At[i] * G1::one(), layer1.A_g1[i]);

            // Bt
            ASSERT_EQ(qap_evaluation.Bt[i] * G1::one(), layer1.B_g1[i]);
            ASSERT_EQ(qap_evaluation.Bt[i] * G2::one(), layer1.B_g2[i]);

            // ABCt
            const Fr ABC_i = beta * qap_evaluation.At[i] +
                             alpha * qap_evaluation.Bt[i] +
                             qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), layer1.ABC_g1[i]);
        }
    }
}

TEST(MPCTests, LinearCombinationReadWrite)
{
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations<ppT>(pot, qap.degree());
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    std::string layer1_serialized;
    {
        std::ostringstream out;
        layer1.write(out);
        layer1_serialized = out.str();
    }

    srs_mpc_layer_L1<ppT> layer1_deserialized = [layer1_serialized]() {
        std::istringstream in(layer1_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_layer_L1<ppT>::read(in);
    }();

    ASSERT_EQ(layer1.T_tau_powers_g1, layer1_deserialized.T_tau_powers_g1);
    ASSERT_EQ(layer1.A_g1, layer1_deserialized.A_g1);
    ASSERT_EQ(layer1.B_g1, layer1_deserialized.B_g1);
    ASSERT_EQ(layer1.B_g2, layer1_deserialized.B_g2);
    ASSERT_EQ(layer1.ABC_g1, layer1_deserialized.ABC_g1);
}

TEST(MPCTests, Layer2)
{
    // Small test circuit and QAP
    protoboard<Fr> pb;
    libzeth::test::simple_circuit<Fr>(pb);
    r1cs_constraint_system<Fr> constraint_system = pb.get_constraint_system();
    constraint_system.swap_AB_if_beneficial();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);

    const size_t n = qap.degree();
    const Fr tau = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr beta = Fr::random_element();
    const Fr delta = Fr::random_element();
    const G1 g1_generator = G1::one();
    const G2 g2_generator = G2::one();

    // dummy POT and pre-compute lagrange evaluations
    srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, n);
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, n);

    // dummy circuit and layer L1
    size_t num_variables = qap.num_variables();
    size_t num_inputs = qap.num_inputs();

    srs_mpc_layer_L1<ppT> lin_comb =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    // layer C2
    srs_mpc_phase2_accumulator<ppT> phase2 =
        srs_mpc_dummy_phase2<ppT>(lin_comb, delta, num_inputs).accumulator;

    // final keypair
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
        std::move(pot),
        std::move(lin_comb),
        std::move(phase2),
        std::move(constraint_system),
        qap);

    // Compare against directly computed values
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            constraint_system.swap_AB_if_beneficial();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau, true);
        })();

        const Fr delta_inverse = delta.inverse();

        // Test Proving Key
        const r1cs_gg_ppzksnark_proving_key<ppT> &pk = keypair.pk;

        ASSERT_EQ(alpha * G1::one(), pk.alpha_g1);
        ASSERT_EQ(beta * G1::one(), pk.beta_g1);
        ASSERT_EQ(beta * G2::one(), pk.beta_g2);
        ASSERT_EQ(delta * G1::one(), pk.delta_g1);
        ASSERT_EQ(delta * G2::one(), pk.delta_g2);

        // H_query
        ASSERT_EQ(qap_evaluation.degree() - 1, pk.H_query.size());
        Fr t_x_i = qap_evaluation.domain->compute_vanishing_polynomial(tau) *
                   delta_inverse;
        for (size_t i = 0; i < pk.H_query.size(); ++i) {
            ASSERT_EQ(t_x_i * G1::one(), pk.H_query[i])
                << "i = " << std::to_string(i);
            t_x_i = tau * t_x_i;
        }

        // L_query
        ASSERT_EQ(num_variables - num_inputs, pk.L_query.size());
        for (size_t i = 0; i < num_variables - num_inputs; ++i) {
            // index into qap_evaluation
            const size_t j = i + num_inputs + 1;

            // ABC / delta
            const Fr ABC_j_over_delta =
                (beta * qap_evaluation.At[j] + alpha * qap_evaluation.Bt[j] +
                 qap_evaluation.Ct[j]) *
                delta_inverse;
            ASSERT_EQ(ABC_j_over_delta * G1::one(), pk.L_query[i])
                << "i = " << std::to_string(i);
        }

        // Test Verification Key
        const r1cs_gg_ppzksnark_verification_key<ppT> &vk = keypair.vk;
        ASSERT_EQ(alpha * G1::one(), vk.alpha_g1);
        ASSERT_EQ(beta * G2::one(), vk.beta_g2);
        ASSERT_EQ(delta * G2::one(), vk.delta_g2);
        ASSERT_EQ(num_inputs, vk.ABC_g1.domain_size());

        const Fr ABC_0 = beta * qap_evaluation.At[0] +
                         alpha * qap_evaluation.Bt[0] + qap_evaluation.Ct[0];
        ASSERT_EQ(ABC_0 * G1::one(), vk.ABC_g1.first);
        for (size_t i = 1; i < vk.ABC_g1.size(); ++i) {
            const Fr ABC_i = beta * qap_evaluation.At[i] +
                             alpha * qap_evaluation.Bt[i] +
                             qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), vk.ABC_g1.rest[i - 1]);
        }
    }

    // Compare with key_pair generated directly from the same secrets.
    {
        const r1cs_constraint_system<Fr> constraint_system = ([&] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> cs = pb.get_constraint_system();
            cs.swap_AB_if_beneficial();
            return cs;
        })();

        const r1cs_gg_ppzksnark_keypair<ppT> keypair2 =
            r1cs_gg_ppzksnark_generator_from_secrets<ppT>(
                constraint_system,
                tau,
                alpha,
                beta,
                delta,
                g1_generator,
                g2_generator,
                true);

        ASSERT_EQ(keypair2.pk.alpha_g1, keypair.pk.alpha_g1);
        ASSERT_EQ(keypair2.pk.beta_g1, keypair.pk.beta_g1);
        ASSERT_EQ(keypair2.pk.beta_g2, keypair.pk.beta_g2);
        ASSERT_EQ(keypair2.pk.delta_g1, keypair.pk.delta_g1);
        ASSERT_EQ(keypair2.pk.delta_g2, keypair.pk.delta_g2);
        ASSERT_EQ(keypair2.pk.A_query, keypair.pk.A_query);
        ASSERT_EQ(keypair2.pk.B_query, keypair.pk.B_query);
        ASSERT_EQ(keypair2.pk.H_query, keypair.pk.H_query);
        ASSERT_EQ(keypair2.pk.L_query, keypair.pk.L_query);

        ASSERT_EQ(keypair2.vk, keypair.vk);
    }

    // Check that the keypair works for proving / verification
    {
        const r1cs_primary_input<Fr> primary{12};
        const r1cs_auxiliary_input<Fr> auxiliary{1, 1, 1};
        const r1cs_gg_ppzksnark_proof<ppT> proof =
            r1cs_gg_ppzksnark_prover(keypair.pk, primary, auxiliary, true);
        ASSERT_TRUE(
            r1cs_gg_ppzksnark_verifier_strong_IC(keypair.vk, primary, proof));
    }
}

TEST(MPCTests, LayerC2ReadWrite)
{
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());
    const srs_mpc_layer_L1<ppT> lin_comb =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);
    const Fr delta = Fr::random_element();
    const srs_mpc_phase2_accumulator<ppT> phase2 =
        srs_mpc_dummy_phase2(lin_comb, delta, qap.num_inputs()).accumulator;

    std::string phase2_serialized;
    {
        std::ostringstream out;
        phase2.write(out);
        phase2_serialized = out.str();
    }

    srs_mpc_phase2_accumulator<ppT> phase2_deserialized =
        [&phase2_serialized]() {
            std::istringstream in(phase2_serialized);
            in.exceptions(
                std::ios_base::eofbit | std::ios_base::badbit |
                std::ios_base::failbit);
            return srs_mpc_phase2_accumulator<ppT>::read(in);
        }();

    ASSERT_EQ(phase2.delta_g1, phase2_deserialized.delta_g1);
    ASSERT_EQ(phase2.delta_g2, phase2_deserialized.delta_g2);
    ASSERT_EQ(phase2.H_g1, phase2_deserialized.H_g1);
    ASSERT_EQ(phase2.L_g1, phase2_deserialized.L_g1);
}

TEST(MPCTests, KeyPairReadWrite)
{
    r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());
    srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);
    const Fr delta = Fr::random_element();
    srs_mpc_phase2_accumulator<ppT> phase2 =
        srs_mpc_dummy_phase2<ppT>(layer1, delta, qap.num_inputs()).accumulator;
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
        std::move(pot),
        std::move(layer1),
        std::move(phase2),
        std::move(constraint_system),
        qap);

    std::string keypair_serialized;
    {
        std::ostringstream out;
        groth16_snark<PP>::keypair_write_bytes(out, keypair);
        keypair_serialized = out.str();
    }

    typename groth16_snark<PP>::KeypairT keypair_deserialized = [&]() {
        std::istringstream in(keypair_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return groth16_snark<PP>::keypair_read_bytes(in);
    }();

    ASSERT_EQ(keypair.pk, keypair_deserialized.pk);
    ASSERT_EQ(keypair.vk, keypair_deserialized.vk);
}

TEST(MPCTests, Phase2PublicKeyReadWrite)
{
    mpc_hash_t empty_hash;
    const uint8_t empty[0]{};
    mpc_compute_hash(empty_hash, empty, 0);

    const size_t seed = 9;
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    const srs_mpc_phase2_publickey<ppT> pubkey =
        srs_mpc_phase2_compute_public_key<ppT>(empty_hash, G1::one(), secret_1);

    std::string pubkey_serialized;
    {
        std::ostringstream out;
        pubkey.write(out);
        pubkey_serialized = out.str();
    }

    srs_mpc_phase2_publickey<ppT> pubkey_deserialized = [&]() {
        std::istringstream in(pubkey_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_publickey<ppT>::read(in);
    }();

    ASSERT_EQ(pubkey, pubkey_deserialized);
}

TEST(MPCTests, Phase2AccumulatorReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_accumulator<ppT> accumulator =
        dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements);

    std::string accumulator_serialized;
    {
        std::ostringstream out;
        accumulator.write(out);
        accumulator_serialized = out.str();
    }

    srs_mpc_phase2_accumulator<ppT> accumulator_deserialized = [&]() {
        std::istringstream in(accumulator_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_accumulator<ppT>::read(in);
    }();

    std::string accumulator_compressed;
    {
        std::ostringstream out;
        accumulator.write_compressed(out);
        accumulator_compressed = out.str();
    }

    srs_mpc_phase2_accumulator<ppT> accumulator_decompressed = [&]() {
        std::istringstream in(accumulator_compressed);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_accumulator<ppT>::read_compressed(in);
    }();

    ASSERT_EQ(accumulator, accumulator_deserialized);
    ASSERT_EQ(accumulator, accumulator_decompressed);
    ASSERT_LT(accumulator_compressed.size(), accumulator_serialized.size());
}

TEST(MPCTests, Phase2ChallengeReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_challenge<ppT> challenge =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));

    std::string challenge_serialized;
    {
        std::ostringstream out;
        challenge.write(out);
        challenge_serialized = out.str();
    }

    srs_mpc_phase2_challenge<ppT> challenge_deserialized = [&]() {
        std::istringstream in(challenge_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_challenge<ppT>::read(in);
    }();

    ASSERT_EQ(
        0,
        memcmp(
            challenge.transcript_digest,
            challenge_deserialized.transcript_digest,
            sizeof(mpc_hash_t)));
    ASSERT_EQ(challenge.accumulator, challenge_deserialized.accumulator);
    ASSERT_EQ(challenge, challenge_deserialized);
}

TEST(MPCTests, Phase2ResponseReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_challenge<ppT> challenge =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));
    const libff::Fr<ppT> secret = libff::Fr<ppT>(seed - 1);
    const srs_mpc_phase2_response<ppT> response =
        srs_mpc_phase2_compute_response<ppT>(challenge, secret);

    std::string response_serialized;
    {
        std::ostringstream out;
        response.write(out);
        response_serialized = out.str();
    }

    srs_mpc_phase2_response<ppT> response_deserialized = [&]() {
        std::istringstream in(response_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_response<ppT>::read(in);
    }();

    ASSERT_EQ(response, response_deserialized);
}

TEST(MPCTests, Phase2Accumulation)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Initial challenge

    const srs_mpc_phase2_challenge<ppT> challenge_0 =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));

    // Participant 1
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    srs_mpc_phase2_response<ppT> response_1 =
        srs_mpc_phase2_compute_response<ppT>(challenge_0, secret_1);
    ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge_0, response_1));
    const srs_mpc_phase2_challenge<ppT> challenge_1 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_1));

    // Participant 2
    const libff::Fr<ppT> secret_2 = libff::Fr<ppT>(seed - 2);
    const srs_mpc_phase2_response<ppT> response_2 =
        srs_mpc_phase2_compute_response<ppT>(challenge_1, secret_2);
    ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge_1, response_2));

    // Verify the size ratio of final accumulator against the original.
    const srs_mpc_phase2_accumulator<ppT> &init_accum = challenge_0.accumulator;
    const srs_mpc_phase2_accumulator<ppT> &final_accum =
        response_2.new_accumulator;
    const libff::Fr<ppT> expect_delta((seed - 1) * (seed - 2));
    const libff::Fr<ppT> expect_delta_inv = expect_delta.inverse();

    ASSERT_EQ(expect_delta * libff::G1<ppT>::one(), final_accum.delta_g1);
    ASSERT_EQ(expect_delta * libff::G2<ppT>::one(), final_accum.delta_g2);
    ASSERT_EQ(init_accum.H_g1.size(), final_accum.H_g1.size());
    for (size_t i = 0; i < init_accum.H_g1.size(); ++i) {
        ASSERT_EQ(expect_delta_inv * init_accum.H_g1[i], final_accum.H_g1[i]);
    }
    ASSERT_EQ(init_accum.L_g1.size(), final_accum.L_g1.size());
    for (size_t i = 0; i < init_accum.L_g1.size(); ++i) {
        ASSERT_EQ(expect_delta_inv * init_accum.L_g1[i], final_accum.L_g1[i]);
    }
}

TEST(MPCTests, Phase2HashToG2)
{
    // Check that independently created source values (at different locations
    // in memory) give the same result.
    const uint8_t empty[0]{};
    mpc_hash_t hash_0;
    mpc_compute_hash(hash_0, empty, 0);
    mpc_hash_t hash_1;
    mpc_compute_hash(hash_1, empty, 0);

    G2 g2_0 = srs_mpc_digest_to_g2<ppT>(hash_0);
    G2 g2_1 = srs_mpc_digest_to_g2<ppT>(hash_1);
    ASSERT_EQ(g2_0, g2_1);
}

TEST(MPCTests, Phase2PublicKeyGeneration)
{
    const size_t seed = 9;
    const libff::Fr<ppT> last_secret(seed - 1);
    const libff::Fr<ppT> secret(seed - 2);
    const uint8_t empty[0]{};
    mpc_hash_t hash;
    mpc_compute_hash(hash, empty, 0);

    const srs_mpc_phase2_publickey<ppT> publickey =
        srs_mpc_phase2_compute_public_key<ppT>(
            hash, last_secret * G1::one(), secret);

    const libff::G2<ppT> r_g2 = srs_mpc_digest_to_g2<ppT>(hash);

    ASSERT_EQ(0, memcmp(hash, publickey.transcript_digest, sizeof(mpc_hash_t)));
    ASSERT_EQ(last_secret * secret * G1::one(), publickey.new_delta_g1);
    ASSERT_EQ(secret * publickey.s_g1, publickey.s_delta_j_g1);
    ASSERT_EQ(secret * r_g2, publickey.r_delta_j_g2);
    ASSERT_TRUE(same_ratio<ppT>(
        last_secret * G1::one(),
        publickey.new_delta_g1,
        r_g2,
        publickey.r_delta_j_g2));
    ASSERT_TRUE(same_ratio<ppT>(
        publickey.s_g1, publickey.s_delta_j_g1, r_g2, publickey.r_delta_j_g2));
    ASSERT_TRUE(
        srs_mpc_phase2_verify_publickey(last_secret * G1::one(), publickey));
}

TEST(MPCTests, Phase2UpdateVerification)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Initial accumulator
    const srs_mpc_phase2_challenge<ppT> challenge(
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements)));
    const libff::Fr<ppT> secret(seed - 1);
    const libff::Fr<ppT> invalid_secret(seed - 2);
    const libff::Fr<ppT> invalid_secret_inv = invalid_secret.inverse();

    // Valid response should pass checks
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        ASSERT_EQ(
            0,
            memcmp(
                challenge.transcript_digest,
                response.publickey.transcript_digest,
                sizeof(mpc_hash_t)));
        ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid publickey.transcript_digest
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.transcript_digest[MPC_HASH_ARRAY_LENGTH / 2] += 1;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent publickey.new_delta_g1
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.new_delta_g1 = invalid_secret * G1::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid $s * delta_j$ in proof-of-knowledge
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.s_delta_j_g1 =
            invalid_secret * response.publickey.s_g1;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid $r * delta_j$ in proof-of-knowledge
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        const libff::G2<ppT> r_g2 =
            srs_mpc_digest_to_g2<ppT>(response.publickey.transcript_digest);
        response.publickey.r_delta_j_g2 = invalid_secret * r_g2;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_1 in new accumulator
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.delta_g1 =
            invalid_secret * libff::G1<ppT>::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_2 in new accumulator
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.delta_g2 =
            invalid_secret * libff::G2<ppT>::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_G2, H_i
    {
        const size_t invalidate_idx = degree / 2;
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.H_g1[invalidate_idx] =
            invalid_secret_inv * challenge.accumulator.H_g1[invalidate_idx];
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_G2, L_i
    {
        const size_t invalidate_idx = num_L_elements / 2;
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.L_g1[invalidate_idx] =
            invalid_secret_inv * challenge.accumulator.L_g1[invalidate_idx];
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }
}

TEST(MPCTests, Phase2TranscriptVerification)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Simulate a transcript with 3 participants.
    const srs_mpc_phase2_challenge<ppT> challenge_0 =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));
    std::ostringstream transcript_out;

    // Participant 1
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    srs_mpc_phase2_response<ppT> response_1 =
        srs_mpc_phase2_compute_response<ppT>(challenge_0, secret_1);
    mpc_hash_t response_1_hash;
    response_1.publickey.compute_digest(response_1_hash);
    response_1.publickey.write(transcript_out);
    const srs_mpc_phase2_challenge<ppT> challenge_1 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_1));

    // Participant 2
    const libff::Fr<ppT> secret_2 = libff::Fr<ppT>(seed - 2);
    srs_mpc_phase2_response<ppT> response_2 =
        srs_mpc_phase2_compute_response<ppT>(challenge_1, secret_2);
    mpc_hash_t response_2_hash;
    response_2.publickey.compute_digest(response_2_hash);
    response_2.publickey.write(transcript_out);
    const srs_mpc_phase2_challenge<ppT> challenge_2 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_2));

    // Participant 3
    const libff::Fr<ppT> secret_3 = libff::Fr<ppT>(seed - 3);
    const srs_mpc_phase2_response<ppT> response_3 =
        srs_mpc_phase2_compute_response<ppT>(challenge_2, secret_3);
    mpc_hash_t response_3_hash;
    response_3.publickey.compute_digest(response_3_hash);
    response_3.publickey.write(transcript_out);
    mpc_hash_t final_digest;
    response_3.publickey.compute_digest(final_digest);

    // Create a transcript
    const std::string transcript = transcript_out.str();

    // Simple verification
    {
        std::istringstream transcript_stream(transcript);
        G1 final_delta_g1;
        mpc_hash_t final_transcript_digest;
        ASSERT_TRUE(srs_mpc_phase2_verify_transcript<ppT>(
            challenge_0.transcript_digest,
            G1::one(),
            transcript_stream,
            final_delta_g1,
            final_transcript_digest));
        ASSERT_EQ(secret_1 * secret_2 * secret_3 * G1::one(), final_delta_g1);
        ASSERT_EQ(
            0,
            memcmp(final_digest, final_transcript_digest, sizeof(mpc_hash_t)));
    }

    // Verify and check for contribution
    {
        std::istringstream transcript_stream(transcript);
        G1 final_delta_g1;
        mpc_hash_t final_transcript_digest;
        bool contribution_found;
        ASSERT_TRUE(srs_mpc_phase2_verify_transcript<ppT>(
            challenge_0.transcript_digest,
            G1::one(),
            response_2_hash,
            transcript_stream,
            final_delta_g1,
            final_transcript_digest,
            contribution_found));
        ASSERT_EQ(secret_1 * secret_2 * secret_3 * G1::one(), final_delta_g1);
        ASSERT_EQ(
            0,
            memcmp(final_digest, final_transcript_digest, sizeof(mpc_hash_t)));
        ASSERT_TRUE(contribution_found);
    }

    // Verify and check for non-existant contribution
    {
        mpc_hash_t no_such_contribution;
        memset(no_such_contribution, 0, sizeof(mpc_hash_t));

        std::istringstream transcript_stream(transcript);
        G1 final_delta_g1;
        mpc_hash_t final_transcript_digest;
        bool contribution_found;
        ASSERT_TRUE(srs_mpc_phase2_verify_transcript<ppT>(
            challenge_0.transcript_digest,
            G1::one(),
            no_such_contribution,
            transcript_stream,
            final_delta_g1,
            final_transcript_digest,
            contribution_found));
        ASSERT_EQ(secret_1 * secret_2 * secret_3 * G1::one(), final_delta_g1);
        ASSERT_EQ(
            0,
            memcmp(final_digest, final_transcript_digest, sizeof(mpc_hash_t)));
        ASSERT_FALSE(contribution_found);
    }
}

} // namespace

int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();

    // Remove stdout noise from libff
    libff::inhibit_profiling_counters = true;
    libff::inhibit_profiling_info = true;

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
