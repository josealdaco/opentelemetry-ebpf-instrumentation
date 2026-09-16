// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	armInstructionSize = 4

	// ARMv8.3 pointer-authenticated returns (PAC), emitted by compilers with
	// -mbranch-protection=standard (default on many arm64 distro and wheel
	// builds, e.g. OpenSSL inside Python cryptography's aarch64 wheels).
	// The arm64asm decoder predates these opcodes and fails to decode them,
	// so they must be matched on the raw instruction word.
	armInstRETAA = 0xD65F0BFF
	armInstRETAB = 0xD65F0FFF
)

func isPACReturn(word uint32) bool {
	return word == armInstRETAA || word == armInstRETAB
}

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index+armInstructionSize <= len(data) {
		word := binary.LittleEndian.Uint32(data[index:])

		if isPACReturn(word) {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		} else if instruction, err := arm64asm.Decode(data[index:]); err == nil &&
			instruction.Op == arm64asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		// arm64 instructions are fixed 4 bytes; advance unconditionally even on
		// decode errors so that truncated or unrecognized words are skipped cleanly.
		index += armInstructionSize
	}

	return returnOffsets, nil
}
