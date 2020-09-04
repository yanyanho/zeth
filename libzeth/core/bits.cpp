// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/utils.hpp"

namespace libzeth
{

std::vector<bool> bits32_to_vector(const bits32 &arr)
{
    return array_to_vector<32>(arr);
}

///function for 64bits
bits64 bits64_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<64>(vect);
}

bits64 bits64_from_hex(const std::string &str)
{
    if (str.length() != 16) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "16)");
    }

    return bits64_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits64_to_vector(const bits64 &arr)
{
    return array_to_vector<64>(arr);
}

///function for 128bits
bits128 bits128_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<128>(vect);
}

bits128 bits128_from_hex(const std::string &str)
{
    if (str.length() != 32) {
        throw std::length_error(
                "Invalid string length for the given hex digest (should be "
                "32)");
    }

    return bits128_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits128_to_vector(const bits128 &arr)
{
    return array_to_vector<128>(arr);
}

///function for 254bits
bits254 bits254_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<254>(vect);
}

bits254 bits254_from_hex(const std::string &str)
{
    return bits254_from_vector(bit_vector_254_from_hex(str));
}

std::vector<bool> bits254_to_vector(const bits254 &arr)
{
    return array_to_vector<254>(arr);
}

///function for 256bits
bits256 bits256_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<256>(vect);
}

bits256 bits256_from_hex(const std::string &str)
{
    if (str.length() != 64) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "64)");
    }

    return bits256_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits256_to_vector(const bits256 &arr)
{
    return array_to_vector<256>(arr);
}

///function for 384bits
bits384 bits384_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<384>(vect);
}

bits384 bits384_from_hex(const std::string &str)
{
    if (str.length() != 96) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "96)");
    }

    return bits384_from_vector(bit_vector_from_hex(str));
}

std::vector<bool> bits384_to_vector(const bits384 &arr)
{
    return array_to_vector<384>(arr);
}

std::vector<bool> bit_vector_from_hex(const std::string &hex_str)
{
    std::vector<bool> result;
    result.reserve(4 * hex_str.size());
    for (char c : hex_str) {
        const uint8_t nibble = char_to_nibble(c);
        result.push_back(nibble & 8);
        result.push_back(nibble & 4);
        result.push_back(nibble & 2);
        result.push_back(nibble & 1);
    }

    return result;
}

std::vector<bool> bit_vector_254_from_hex(const std::string &hex_str)
{
    std::vector<bool> result;
    result.reserve(4 * hex_str.size());
    for (char c : hex_str) {
        const uint8_t nibble = char_to_nibble(c);
        result.push_back(nibble & 8);
        result.push_back(nibble & 4);
        result.push_back(nibble & 2);
        result.push_back(nibble & 1);
    }
    std::vector<bool> last;
    last.reserve(254);
    for (auto i = result.begin(); i < result.end();) {
        if(*i != 0) {
            last.assign(i, result.end());
            break;}
        else{
            i++;
        }
    }
    while(last.size() < 254){
        last.insert(last.begin(), 0);
    }
    return last;
}

std::vector<bool> bit_vector_from_size_t_le(size_t x)
{
    std::vector<bool> ret;
    while (x) {
        if (x & 1) {
            ret.push_back(1);
        } else {
            ret.push_back(0);
        }
        x >>= 1;
    }

    return ret;
}

std::vector<bool> bit_vector_from_size_t_be(size_t n)
{
    std::vector<bool> res;
    size_t num_bits = 8 * sizeof(size_t);
    const size_t mask = 1ull << (num_bits - 1);

    // Remove 0-bits at the front
    while (num_bits > 0) {
        if ((n & mask) != 0) {
            break;
        }
        n = n << 1;
        --num_bits;
    }

    // Pre-allocate and fill the vector with remaining bits
    res.reserve(num_bits);
    while (num_bits > 0) {
        if ((n & mask) != 0) {
            res.push_back(true);
        } else {
            res.push_back(false);
        }

        n = n << 1;
        --num_bits;
    }

    return res;
}

} // namespace libzeth
