// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"

namespace libzeth
{

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note)
{
    std::cout << "parse zeth_note" << std::endl;
    std::cout << note.apk() << std::endl;
    bits254 note_apk = bits254_from_hex(note.apk());
    std::cout << note.value() << std::endl;
    bits64 note_value = bits64_from_hex(note.value());
    std::cout << note.rho() << std::endl;
    bits254 note_rho = bits254_from_hex(note.rho());
    std::cout << note.trap_r() << std::endl;
    bits254 note_trap_r = bits254_from_hex(note.trap_r());
    std::cout << "after parse zeth_note" << std::endl;

    return zeth_note(note_apk, note_value, note_rho, note_trap_r);
}

} // namespace libzeth
