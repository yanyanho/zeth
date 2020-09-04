// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_NOTE_HPP__
#define __ZETH_CORE_NOTE_HPP__

#include "libzeth/core/bits.hpp"

#include <array>

namespace libzeth
{

class zeth_note
{
public:
    bits254 a_pk;
    bits64 value;
    bits254 rho;
    bits254 r;

    zeth_note(bits254 a_pk, bits64 value, bits254 rho, bits254 r)
        : a_pk(a_pk), value(value), rho(rho), r(r)
    {
    }

    zeth_note() { value.fill(false); }

    inline bool is_zero_valued() const
    {
        for (const bool b : value) {
            if (b) {
                return false;
            }
        }
        return true;
    }
};

} // namespace libzeth

#endif // __ZETH_CORE_NOTE_HPP__
