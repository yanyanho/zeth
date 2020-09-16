#ifndef __ZETH_CIRCUITS_POSEIDON_HPP_
#define __ZETH_CIRCUITS_POSEIDON_HPP_

// Copyright (c) 2019 xxb
// License: LGPL-3.0+

#include "blake2b.hpp"

#include <mutex>

namespace libzeth {

using libsnark::linear_combination;
using libsnark::linear_term;

template<typename FieldT>
struct PoseidonConstants
{
	std::vector<FieldT> C; // `t` constants
	std::vector<FieldT> M; // `t * t` matrix of constants
};

template<typename FieldT>
class FifthPower_gadget : public libsnark::gadget<FieldT> {
public:
	libsnark::pb_variable<FieldT> x2;
	libsnark::pb_variable<FieldT> x4;
	libsnark::pb_variable<FieldT> x5;

	FifthPower_gadget(
	        libsnark::protoboard<FieldT> &pb,
		const std::string& annotation_prefix
	) :
       libsnark::gadget<FieldT>(pb, annotation_prefix)
	{
        x2.allocate(
                pb, FMT(this->annotation_prefix, ".x2"));
        x4.allocate(
                pb, FMT(this->annotation_prefix, ".x4"));
        x5.allocate(
                pb, FMT(this->annotation_prefix, ".x5"));
	}

	void generate_r1cs_constraints(const linear_combination<FieldT>& x) const
	{
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(x, x, x2), FMT(this->annotation_prefix, ".x^2 = x * x"));
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(x2, x2, x4), FMT(this->annotation_prefix, ".x^4 = x2 * x2"));
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(x, x4, x5), FMT(this->annotation_prefix, ".x^5 = x * x4"));
	}

	void generate_r1cs_witness(const FieldT& val_x) const
    {
    	const auto val_x2 = val_x * val_x;
    	const auto val_x4 = val_x2 * val_x2;
    	const auto val_x5 = val_x4 * val_x;
    	this->pb.val(x2) = val_x2;
    	this->pb.val(x4) = val_x4;
    	this->pb.val(x5) = val_x5;
    }

    const libsnark::pb_variable<FieldT>& result() const
    {
    	return x5;
    }
};
template<typename FieldT>
static FieldT bytes_to_FieldT( const uint8_t *in_bytes, const size_t in_count, int order )
{
        const unsigned n_bits_roundedup = FieldT::size_in_bits() + (8 - (FieldT::size_in_bits()%8));
        const unsigned n_bytes = n_bits_roundedup / 8;

        assert( in_count <= n_bytes );

        // Import bytes as big-endian
        mpz_t result_as_num;
        mpz_init(result_as_num);
        mpz_import(result_as_num,       // rop
                   in_count,            // count
                   order,               // order
                   1,                   // size
                   0,                   // endian
                   0,                   // nails
                   in_bytes);           // op

        // Convert to bigint, within F_p
        libff::bigint<FieldT::num_limbs> item(result_as_num);
        assert( sizeof(item.data) == n_bytes );
        mpz_clear(result_as_num);

        return FieldT(item);
}
template<typename FieldT>
FieldT bytes_to_FieldT_littleendian( const uint8_t *in_bytes, const size_t in_count )
{
    return bytes_to_FieldT<FieldT>(in_bytes, in_count, -1);
}

template<typename FieldT>
static void poseidon_constants_fill(const std::string &seed, unsigned n_constants, std::vector<FieldT> &result )
{
	blake2b_ctx ctx;

	const unsigned n_bits_roundedup = FieldT::size_in_bits() + (8 - (FieldT::size_in_bits()%8));
	const unsigned output_size = n_bits_roundedup / 8;
	uint8_t output[output_size];

	result.reserve(n_constants);

	blake2b(output, output_size, NULL, 0, seed.c_str(), seed.size());
	result.emplace_back( bytes_to_FieldT_littleendian<FieldT>(output, output_size) );

	for( unsigned i = 0; i < (n_constants - 1); i++ )
	{
		blake2b(output, output_size, NULL, 0, output, output_size);
		result.emplace_back( bytes_to_FieldT_littleendian<FieldT>(output, output_size) );
	}
}

template<typename FieldT>
static const std::vector<FieldT> poseidon_constants(const std::string &seed, unsigned n_constants)
{
	std::vector<FieldT> result;
	poseidon_constants_fill(seed, n_constants, result);
	return result;
}

template<typename FieldT>
static void poseidon_matrix_fill(const std::string &seed, unsigned t, std::vector<FieldT> &result)
{
	const std::vector<FieldT> c = poseidon_constants<FieldT>(seed, t*2);

	result.reserve(t*2);

	for( unsigned i = 0; i < t; i++ )
	{
		for( unsigned j = 0; j < t; j++ )
		{		
			result.emplace_back((c[i] - c[t+j]).inverse());
		}
	}
}

template<typename FieldT>
static const std::vector<FieldT> poseidon_matrix(const std::string &seed, unsigned t)
{
	std::vector<FieldT> result;
	poseidon_matrix_fill(seed, t, result);
	return result;
}


template<unsigned param_t, unsigned param_F, unsigned param_P, typename FieldT>
PoseidonConstants<FieldT>& poseidon_params()
{
    static PoseidonConstants<FieldT> constants;
    static std::once_flag flag;

    std::call_once(flag, [](){
    	poseidon_constants_fill<FieldT>("poseidon_constants", param_F + param_P, constants.C);
        poseidon_matrix_fill("poseidon_matrix_0000", param_t, constants.M);
    });

    return constants;
}
template<typename FieldT>
std::vector<libsnark::linear_combination<FieldT>> VariableArrayT_to_lc( const libsnark::pb_variable_array<FieldT>& in_vars )
{
    std::vector<libsnark::linear_combination<FieldT> > ret;
    ret.reserve(in_vars.size());
    for( const auto& var : in_vars ) {
        ret.emplace_back(var);
    }
    return ret;
}
template<typename FieldT>
FieldT lc_val( const libsnark::protoboard<FieldT>& pb, const libsnark::linear_combination<FieldT>& in_lc )
{
    FieldT sum = 0;
    for ( const auto &term : in_lc.terms)
    {
        sum += term.coeff * pb.val(libsnark::pb_variable<FieldT>(term.index));
    }
    return sum;
}
/**
* One round of the Poseidon permutation:
*
*    - takes a state of `t` elements
*    - adds the round constant to each element in the state
*    - performs exponentiation on the first `n` elements of the state
*    - creates `o` outputs, mixed using a matrix vector transform
*
* This generic version can be used as either a 'full', 'partial' or 'last' round.
* It avoids computing as many constraints as is possible, given all the information.
*/
template<unsigned param_t, unsigned nSBox, unsigned nInputs, unsigned nOutputs, typename FieldT>
class Poseidon_Round : public libsnark::gadget<FieldT> {
public:		
	const FieldT& C_i;
    const std::vector<FieldT>& M;
    const std::vector<libsnark::linear_combination<FieldT> > state;
    const std::vector<FifthPower_gadget<FieldT>> sboxes;
	const std::vector<libsnark::linear_combination<FieldT> > outputs;

	static std::vector<FifthPower_gadget<FieldT>> make_sboxes(
            libsnark::protoboard<FieldT>& in_pb,
		const std::string& annotation_prefix )
	{
		std::vector<FifthPower_gadget<FieldT>> ret;

		ret.reserve(nSBox);
		for( unsigned h = 0; h < nSBox; h++ )
		{
			ret.emplace_back( in_pb, FMT(annotation_prefix, ".sbox[%u]", h) );
		}

		return ret;
	}

	static std::vector<libsnark::linear_combination<FieldT> > make_outputs(
            libsnark::protoboard<FieldT>& in_pb,
            const FieldT& in_C_i,
            const std::vector<FieldT>& in_M,
            const std::vector<libsnark::linear_combination<FieldT> >& in_state,
            const std::vector<FifthPower_gadget<FieldT>>& in_sboxes )
	{
		std::vector<libsnark::linear_combination<FieldT> > ret;

		for( unsigned i = 0; i < nOutputs; i++ )
		{
			const unsigned M_offset = i * param_t;

			// Any element which isn't passed through an sbox
			// Can be accumulated separately as part of the constant term
			FieldT constant_term;
			for( unsigned j = nSBox; j < param_t; j++ ) {
				constant_term += in_C_i * in_M[M_offset+j];
			}

			linear_combination<FieldT> lc;
			lc.terms.reserve(param_t);
			if( nSBox < param_t )
			{
				lc.add_term(ONE, constant_term);
			}			

			// Add S-Boxes to the output row
			for( unsigned s = 0; s < nSBox; s++ )
			{
				lc.add_term(in_sboxes[s].result(), in_M[M_offset+s]);
			}

			// Then add inputs (from the state) multiplied by the matrix element
			for( unsigned k = nSBox; k < nInputs; k++ )
			{
				lc = lc + (in_state[k] * in_M[M_offset+k]);
			}

			ret.emplace_back(lc);
		}
		return ret;
	}

	Poseidon_Round(
            libsnark::protoboard<FieldT> &in_pb,
            const FieldT& in_C_i,
            const std::vector<FieldT>& in_M,
            const libsnark::pb_variable_array<FieldT>& in_state,
		const std::string& annotation_prefix
	) :
		Poseidon_Round(in_pb, in_C_i, in_M, VariableArrayT_to_lc(in_state), annotation_prefix)
	{ }

	Poseidon_Round(
            libsnark::protoboard<FieldT> &in_pb,
            const FieldT& in_C_i,
            const std::vector<FieldT>& in_M,
            const std::vector<libsnark::linear_combination<FieldT> >& in_state,
            const std::string& annotation_prefix
	) :
            libsnark::gadget<FieldT>(in_pb, annotation_prefix),
		C_i(in_C_i),
		M(in_M),
		state(in_state),
		sboxes(make_sboxes(in_pb, annotation_prefix)),
		outputs(make_outputs(in_pb, in_C_i, in_M, in_state, sboxes))
	{
		assert( nInputs <= param_t );
		assert( nOutputs <= param_t );
	}

	void generate_r1cs_witness() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			auto value = C_i;
			if( h < nInputs ) {
				value += lc_val<FieldT>(this->pb, state[h]); // this->pb.val(state[h]);
			}
			sboxes[h].generate_r1cs_witness( value );
		}
	}

	void generate_r1cs_constraints() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			if( h < nInputs ) {
				sboxes[h].generate_r1cs_constraints( state[h] + C_i );
			}
			else {
				sboxes[h].generate_r1cs_constraints( C_i );
			}
		}
	}
};


template<unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, unsigned nInputs, unsigned nOutputs, typename FieldT, bool constrainOutputs=true>
class Poseidon_gadget_T : public libsnark::gadget<FieldT>
{
protected:
	typedef Poseidon_Round<param_t, param_t, nInputs, param_t, FieldT> FirstRoundT;    // ingests `nInput` elements, expands to `t` elements using round constants
	typedef Poseidon_Round<param_t, param_c, param_t, param_t, FieldT> PartialRoundT;  // partial round only runs sbox on `c` elements (capacity)
	typedef Poseidon_Round<param_t, param_t, param_t, param_t, FieldT> FullRoundT;     // full bandwidth
	typedef Poseidon_Round<param_t, param_t, param_t, nOutputs, FieldT> LastRoundT;   // squeezes state into `nOutputs`

	typedef const std::vector<libsnark::linear_combination<FieldT> >& lc_outputs_t;
	typedef const libsnark::linear_combination<FieldT>& lc_output_t;
	typedef const libsnark::pb_variable<FieldT>& var_output_t;
	typedef const libsnark::pb_variable_array<FieldT>& var_outputs_t;

	static constexpr unsigned partial_begin = (param_F/2);
	static constexpr unsigned partial_end = (partial_begin + param_P);
	static constexpr unsigned total_rounds = param_F + param_P;

public:
    const libsnark::pb_variable<FieldT> x;
    const libsnark::pb_variable<FieldT> y;
    const libsnark::pb_variable_array<FieldT>& inputs;
	const PoseidonConstants<FieldT>& constants;
	
	FirstRoundT first_round;	
	std::vector<FullRoundT> prefix_full_rounds;
	std::vector<PartialRoundT> partial_rounds;
	std::vector<FullRoundT> suffix_full_rounds;
	LastRoundT last_round;

	// When `constrainOutputs==true`, need variables to store outputs
	const libsnark::pb_variable_array<FieldT> _output_vars;

	template<typename T>
	static const std::vector<T> make_rounds(
		unsigned n_begin, unsigned n_end,
        libsnark::protoboard<FieldT>& pb,
		const std::vector<libsnark::linear_combination<FieldT> >& inputs,
		const PoseidonConstants<FieldT>& constants,
		const std::string& annotation_prefix)
	{
		std::vector<T> result;
		result.reserve(n_end - n_begin);

		for( unsigned i = n_begin; i < n_end; i++ )
		{
			const auto& state = (i == n_begin) ? inputs : result.back().outputs;
			result.emplace_back(pb, constants.C[i], constants.M, state, FMT(annotation_prefix, ".round[%u]", i));
		}

		return result;
	}

    const libsnark::pb_variable_array<FieldT> make_var_array( libsnark::protoboard<FieldT> &in_pb, size_t n, const std::string &annotation )
    {
        libsnark::pb_variable_array<FieldT> x;
        x.allocate(in_pb, n, annotation);
        return x;
    }

    const libsnark::pb_variable_array<FieldT> make_var_array( libsnark::protoboard<FieldT> &in_pb, const std::string &annotation, std::vector<FieldT> values )
    {
        auto vars = make_var_array(in_pb, values.size(), annotation);
        for( unsigned i = 0; i < values.size(); i++ )
        {
            in_pb.val(vars[i]) = values[i];
        }
        return vars;
    }
    const libsnark::pb_variable_array<FieldT> make_var_array( libsnark::protoboard<FieldT> &in_pb, const std::string &annotation,
            const libsnark::pb_variable<FieldT> x, const libsnark::pb_variable<FieldT> y )
    {
        libsnark::pb_variable_array<FieldT> ar;
        ar.allocate(in_pb, 2, annotation);
        ar[0] = x;
        ar[1] = y;
        return ar;
    }
    inline std::vector<FieldT> vals( const libsnark::protoboard<FieldT>& pb, const std::vector<libsnark::linear_combination<FieldT> > &in_lcs ) const
    {
        std::vector<FieldT> ret;
        ret.reserve(in_lcs.size());
        for( const auto &lc : in_lcs )
        {
            ret.emplace_back(lc_val<FieldT>(pb, lc));
        }
        return ret;
    }

    inline std::vector<FieldT> vals( const libsnark::protoboard<FieldT>& pb, const libsnark::pb_variable_array<FieldT> &in_vars ) const
    {
        return in_vars.get_vals(pb);
    }
    /*
	static std::vector<FieldT> permute( std::vector<FieldT> inputs )
	{
        libsnark::protoboard<FieldT> pb;

		assert( inputs.size() == nInputs );
		auto var_inputs = make_var_array(pb, "input", inputs);

		Poseidon_gadget_T<param_t, param_c, param_F, param_P, nInputs, nOutputs, FieldT> gadget(pb, var_inputs, "gadget");
		gadget.generate_r1cs_witness();

		return vals(pb, gadget.results());
	}
    */
    static FieldT get_hash(const FieldT x, FieldT y)
    {
        libsnark::protoboard<FieldT> pb;
        libsnark::pb_variable_array<FieldT> ar;

        ar.allocate(pb, 2, "ar");
        pb.val(ar[0]) = x;
        pb.val(ar[1]) = y;
        Poseidon_gadget_T<6, 1, 8, 57, 2, 1, FieldT> hasher (pb, ar[0], ar[1], "gadget");
        hasher.generate_r1cs_witness();

        return pb.val(hasher.result());
    }
    static size_t get_digest_len()
    {
        return 254;
    }
	Poseidon_gadget_T(
            libsnark::protoboard<FieldT> &pb,
		//const libsnark::pb_variable_array<FieldT> in_inputs,
		libsnark::pb_variable<FieldT> x,
		libsnark::pb_variable<FieldT> y,
		const std::string& annotation_prefix
	) :
        libsnark::gadget<FieldT>(pb, annotation_prefix),
        x(x),
        y(y),
		inputs(make_var_array(pb, "inputs", x, y)),
		constants(poseidon_params<param_t, param_F, param_P, FieldT>()),
		first_round(pb, constants.C[0], constants.M, make_var_array(pb, "inputs", x, y), FMT(annotation_prefix, ".round[0]")),
		prefix_full_rounds(
			make_rounds<FullRoundT>(
				1, partial_begin, pb,
				first_round.outputs, constants, annotation_prefix)),
		partial_rounds(
			make_rounds<PartialRoundT>(
				partial_begin, partial_end, pb,
				prefix_full_rounds.back().outputs, constants, annotation_prefix)),
		suffix_full_rounds(
			make_rounds<FullRoundT>(
				partial_end, total_rounds-1, pb,
				partial_rounds.back().outputs, constants, annotation_prefix)),
		last_round(pb, constants.C.back(), constants.M, suffix_full_rounds.back().outputs, FMT(annotation_prefix, ".round[%u]", total_rounds-1)),
		_output_vars(constrainOutputs ? make_var_array(pb, nOutputs, ".output") : libsnark::pb_variable_array<FieldT>())
	{
	}

	template<bool x = constrainOutputs>
	typename std::enable_if<!x, lc_outputs_t>::type
	results() const
	{
		return last_round.outputs;
	}

	template<bool x = constrainOutputs>
	typename std::enable_if<x, var_outputs_t>::type
	results() const
	{
		return _output_vars;
	}

	template<bool x = constrainOutputs, unsigned n = nOutputs>
	typename std::enable_if<!x && n == 1 , lc_output_t>::type
	result() const
	{
		return last_round.outputs[0];
	}

	template<bool x = constrainOutputs, unsigned n = nOutputs>
	typename std::enable_if<x && n == 1, var_output_t>::type
	result() const
	{
		return _output_vars[0];
	}

	void generate_r1cs_constraints() const
	{
		first_round.generate_r1cs_constraints();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_constraints();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_constraints();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_constraints();
		}

		last_round.generate_r1cs_constraints();

		if( constrainOutputs )
		{
			unsigned i = 0;
			for( const auto &lc : last_round.outputs )
			{
				this->pb.add_r1cs_constraint(
                        libsnark::r1cs_constraint<FieldT>(lc, ONE, _output_vars[i]),
					FMT(this->annotation_prefix, ".output[%u] = last_round.output[%u]", i, i));
				i += 1;
			}
		}
	}


	void generate_r1cs_witness() const
	{
		first_round.generate_r1cs_witness();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_witness();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_witness();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_witness();
		}

		last_round.generate_r1cs_witness();

		// When outputs are constrained, fill in the variable
		if( constrainOutputs )
		{
			unsigned i = 0;
			for( const auto &value : vals(this->pb, last_round.outputs) )
			{
				this->pb.val(_output_vars[i++]) = value;
			}
		}
	}
};


template<unsigned nInputs, unsigned nOutputs, typename FieldT, bool constrainOutputs=true>
using Poseidon128 = Poseidon_gadget_T<6, 1, 8, 57, nInputs, nOutputs, FieldT, constrainOutputs>;


// namespace libzeth
}

#endif
