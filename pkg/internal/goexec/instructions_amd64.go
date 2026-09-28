// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"golang.org/x/arch/x86/x86asm"
)

const endbrSize = 4

// isENDBRXX matches ENDBR64/ENDBR32 (Intel CET landing pads) on the raw
// instruction bytes. Like the pointer-authenticated returns handled in the
// arm64 scanner (isPACReturn), these are newer ISA additions that the
// x/arch decoder predates: without this check the scan would stop at the
// very first instruction of any CET-enabled function.
//
// Note: x86-64 has no equivalent of arm64's RETAA/RETAB. Pointer
// authentication is an ARMv8.3 feature; x86 returns are always plain RET
// (0xC3/0xC2), which the decoder handles. The failure class shared between
// the two architectures is decoder blind spots, not the PAC opcodes.
func isENDBRXX(data []uint8) bool {
	if len(data) < endbrSize {
		return false
	}

	return data[0] == 0xF3 &&
		data[1] == 0x0F &&
		data[2] == 0x1E &&
		(data[3] == 0xFA || data[3] == 0xFB)
}

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		// FIXME remove this once x86asm is able to recognize and decode
		// ENDBR64
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}

		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			// An instruction the decoder does not know (newer ISA extension,
			// data island, padding). x86 instructions are variable-length, so
			// the stream cannot be resynchronized reliably past this point:
			// keep the offsets collected so far instead of failing the whole
			// symbol, which would silently drop its return probes (the same
			// failure mode the PAC handling avoids on arm64).
			break
		}

		if instruction.Op == x86asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		index += instruction.Len
	}

	return returnOffsets, nil
}
