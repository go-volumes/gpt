// Package gpt is a single hardened MBR + GPT partition-table parser for the
// go-filesystems drivers, replacing seven duplicated and individually buggy
// copies (ext4, xfs, btrfs, apfs, zfs, exfat, fat32).
//
// It parses UNTRUSTED on-disk images, so every length, count, and offset is
// validated before use: the partition-entry size and count are capped, the
// entry-array LBA and every partition's start and length are validated
// against the device size, all offset arithmetic is performed in int64 to
// reject overflow, and a truncated or short header returns an error instead
// of panicking. It never auto-follows nonsensical geometry.
//
// Pure Go, no dependencies outside the standard library, go 1.25 / CGO=0.
package gpt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SectorSize is the LBA size assumed for both MBR and GPT. Every image these
// drivers handle (hdiutil, mkfs, newfs_*, parted defaults) uses 512-byte
// logical sectors; 4Kn images are out of scope, matching all seven callers.
const SectorSize = 512

// Hardening bounds. Anything outside these is treated as a malformed image.
const (
	// MinEntrySize is the smallest legal GPT partition-entry size (UEFI 2.x).
	MinEntrySize = 128
	// MaxEntrySize caps the entry size to defeat class-(A) over-allocation.
	MaxEntrySize = 4096
	// MaxPartitionEntries caps the entry count. UEFI's canonical layout has
	// 128; we allow up to this many to stay safe against a hostile count
	// such as 0xFFFFFFFF.
	MaxPartitionEntries = 256
)

// ErrGPT is the base error every sentinel below wraps, so callers can match
// the whole family with errors.Is(err, ErrGPT).
var ErrGPT = errors.New("gpt")

var (
	// ErrNoTable means neither a GPT header nor an MBR signature was found:
	// the image is a bare filesystem with no partition table.
	ErrNoTable = fmt.Errorf("%w: no partition table", ErrGPT)
	// ErrMalformed means a partition table was present but its contents were
	// inconsistent, out of range, or impossibly sized.
	ErrMalformed = fmt.Errorf("%w: malformed partition table", ErrGPT)
	// ErrNotFound means the requested partition index, or an auto-selected
	// partition of the desired type, does not exist.
	ErrNotFound = fmt.Errorf("%w: partition not found", ErrGPT)
)

// Scheme identifies which partitioning scheme a [Partition] came from.
type Scheme int

const (
	// SchemeMBR is a classic 4-entry MBR partition table.
	SchemeMBR Scheme = iota
	// SchemeGPT is a GUID Partition Table.
	SchemeGPT
)

func (s Scheme) String() string {
	switch s {
	case SchemeMBR:
		return "MBR"
	case SchemeGPT:
		return "GPT"
	default:
		return fmt.Sprintf("Scheme(%d)", int(s))
	}
}

// Partition describes one validated partition. All byte offsets and lengths
// are absolute, in bytes, relative to the start of the device, and are
// guaranteed to satisfy 0 <= StartOffset and StartOffset+Length <= deviceSize.
type Partition struct {
	// Index is the 0-based slot in the table (GPT entry index, or MBR slot
	// 0..3). For GPT, empty (all-zero type GUID) slots are skipped, so Index
	// values may be non-contiguous.
	Index int
	// Scheme records whether this came from MBR or GPT.
	Scheme Scheme
	// StartOffset is the partition's first byte from the device start.
	StartOffset int64
	// Length is the partition size in bytes. For MBR it is derived from the
	// 32-bit sector count; it may be 0 if the on-disk count was 0.
	Length int64
	// TypeGUID is the GPT partition type GUID in on-disk ("wire") byte order.
	// Zero for MBR partitions.
	TypeGUID [16]byte
	// MBRType is the 1-byte MBR partition type (e.g. 0x83 Linux, 0xEE
	// protective). Zero for GPT partitions.
	MBRType byte
	// Name is the GPT partition name (UTF-16LE decoded to UTF-8). Empty for
	// MBR partitions.
	Name string
}

// Well-known GPT partition type GUIDs in on-disk ("wire") byte order, for
// callers that auto-select by type. Mixed-endian per UEFI: first three
// groups little-endian, the rest big-endian.
var (
	// LinuxFilesystemGUID is 0FC63DAF-8483-4772-8E79-3D69D8477DE4.
	LinuxFilesystemGUID = [16]byte{
		0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
		0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
	}
	// AppleAPFSGUID is 7C3457EF-0000-11AA-AA11-00306543ECAC.
	AppleAPFSGUID = [16]byte{
		0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11,
		0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC,
	}
)

var zeroGUID [16]byte

// List parses the partition table at the start of r and returns every
// populated partition, validated against deviceSize. A protective-MBR that
// fronts a GPT is transparently followed to the GPT. A bare image (no GPT
// header, no MBR signature) returns ([]Partition(nil), [ErrNoTable]).
//
// deviceSize must be > 0; pass the image/device size in bytes. It is used to
// reject partitions or entry arrays that fall outside the device.
func List(r io.ReaderAt, deviceSize int64) ([]Partition, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrMalformed)
	}
	if deviceSize <= 0 {
		return nil, fmt.Errorf("%w: non-positive device size %d", ErrMalformed, deviceSize)
	}

	// GPT primary header lives at LBA 1.
	var sig [8]byte
	if _, err := r.ReadAt(sig[:], SectorSize); err == nil && string(sig[:]) == "EFI PART" {
		return listGPT(r, deviceSize)
	}

	// Otherwise look for an MBR signature at bytes 510..511. A protective MBR
	// that fronts a GPT (single type-0xEE entry) is handled transparently:
	// the GPT probe above already followed the real table when its "EFI PART"
	// signature was present, so reaching here with a 0xEE entry simply means
	// the GPT header was absent or unreadable and we return the MBR view.
	var magic [2]byte
	if _, err := r.ReadAt(magic[:], 510); err == nil && magic[0] == 0x55 && magic[1] == 0xAA {
		return listMBR(r, deviceSize)
	}

	return nil, ErrNoTable
}

func listGPT(r io.ReaderAt, deviceSize int64) ([]Partition, error) {
	// Read the 92-byte GPT header from LBA 1. A short read here means a
	// truncated image: return an error, never panic.
	hdr := make([]byte, 92)
	if _, err := r.ReadAt(hdr, SectorSize); err != nil {
		return nil, fmt.Errorf("%w: read header: %v", ErrMalformed, err)
	}
	le := binary.LittleEndian
	partEntryLBA := le.Uint64(hdr[72:80])
	numParts := le.Uint32(hdr[80:84])
	entrySize := le.Uint32(hdr[84:88])

	// Bound the entry size (class A) and reject impossible values.
	if entrySize < MinEntrySize || entrySize > MaxEntrySize {
		return nil, fmt.Errorf("%w: entry size %d out of range [%d,%d]",
			ErrMalformed, entrySize, MinEntrySize, MaxEntrySize)
	}
	// Bound the entry count.
	if numParts == 0 {
		return nil, fmt.Errorf("%w: zero partition entries", ErrMalformed)
	}
	if numParts > MaxPartitionEntries {
		return nil, fmt.Errorf("%w: %d partition entries exceeds max %d",
			ErrMalformed, numParts, MaxPartitionEntries)
	}

	// Validate the entry-array LBA and its byte extent against the device.
	if partEntryLBA == 0 {
		return nil, fmt.Errorf("%w: zero partition-entry LBA", ErrMalformed)
	}
	tableOff, ok := mul64(int64(partEntryLBA), SectorSize)
	if !ok || tableOff < 0 {
		return nil, fmt.Errorf("%w: partition-entry LBA %d overflows", ErrMalformed, partEntryLBA)
	}
	// numParts <= MaxPartitionEntries (256) and entrySize <= MaxEntrySize
	// (4096), so this product cannot overflow int64.
	tableLen := int64(numParts) * int64(entrySize)
	tableEnd, ok := add64(tableOff, tableLen)
	if !ok || tableEnd > deviceSize {
		return nil, fmt.Errorf("%w: entry array [%d,%d) exceeds device size %d",
			ErrMalformed, tableOff, tableEnd, deviceSize)
	}

	parts := make([]Partition, 0, numParts)
	buf := make([]byte, entrySize)
	for i := uint32(0); i < numParts; i++ {
		off := tableOff + int64(i)*int64(entrySize)
		if _, err := r.ReadAt(buf, off); err != nil {
			// Truncated entry array: stop, return what validated so far.
			break
		}
		var typeGUID [16]byte
		copy(typeGUID[:], buf[0:16])
		if typeGUID == zeroGUID {
			continue // unused slot
		}
		startLBA := le.Uint64(buf[32:40])
		endLBA := le.Uint64(buf[40:48])

		start, ok := mul64(int64(startLBA), SectorSize)
		if !ok || start < 0 || start > deviceSize {
			return nil, fmt.Errorf("%w: partition %d start LBA %d out of range",
				ErrMalformed, i, startLBA)
		}
		// endLBA is inclusive; length = (end-start+1) sectors. Tolerate a
		// zero/!plausible end by clamping the partition to the device.
		var length int64
		if endLBA >= startLBA {
			sectors, ok := add64(int64(endLBA-startLBA), 1)
			if !ok {
				return nil, fmt.Errorf("%w: partition %d length overflows", ErrMalformed, i)
			}
			length, ok = mul64(sectors, SectorSize)
			if !ok {
				return nil, fmt.Errorf("%w: partition %d byte length overflows", ErrMalformed, i)
			}
		}
		end, ok := add64(start, length)
		if !ok || end > deviceSize {
			return nil, fmt.Errorf("%w: partition %d [%d,%d) exceeds device size %d",
				ErrMalformed, i, start, end, deviceSize)
		}

		parts = append(parts, Partition{
			Index:       int(i),
			Scheme:      SchemeGPT,
			StartOffset: start,
			Length:      length,
			TypeGUID:    typeGUID,
			Name:        decodeUTF16Name(buf, int(entrySize)),
		})
	}
	return parts, nil
}

// decodeUTF16Name decodes the 72-byte UTF-16LE partition name at offset 56
// of a GPT entry, stopping at the first NUL. It is bounds-safe against a
// short entry buffer.
func decodeUTF16Name(buf []byte, entrySize int) string {
	const nameOff = 56
	const nameMax = 72 // 36 UTF-16 code units
	end := nameOff + nameMax
	if entrySize < end {
		end = entrySize
	}
	if end > len(buf) {
		end = len(buf)
	}
	if end <= nameOff {
		return ""
	}
	var runes []rune
	for i := nameOff; i+1 < end; i += 2 {
		u := binary.LittleEndian.Uint16(buf[i : i+2])
		if u == 0 {
			break
		}
		runes = append(runes, rune(u))
	}
	return string(runes)
}

func listMBR(r io.ReaderAt, deviceSize int64) ([]Partition, error) {
	table := make([]byte, 64) // 4 × 16-byte entries at offset 446
	if _, err := r.ReadAt(table, 446); err != nil {
		return nil, fmt.Errorf("%w: read MBR table: %v", ErrMalformed, err)
	}
	parts := make([]Partition, 0, 4)
	for i := 0; i < 4; i++ {
		e := table[i*16 : i*16+16]
		ptype := e[4]
		startLBA := binary.LittleEndian.Uint32(e[8:12])
		numSectors := binary.LittleEndian.Uint32(e[12:16])
		if ptype == 0 && startLBA == 0 && numSectors == 0 {
			continue // empty slot
		}
		start, ok := mul64(int64(startLBA), SectorSize)
		if !ok || start < 0 || start > deviceSize {
			return nil, fmt.Errorf("%w: MBR partition %d start LBA %d out of range",
				ErrMalformed, i, startLBA)
		}
		// numSectors is a uint32, so numSectors*512 fits comfortably in int64
		// and cannot overflow.
		length := int64(numSectors) * SectorSize
		end, ok := add64(start, length)
		if !ok || end > deviceSize {
			return nil, fmt.Errorf("%w: MBR partition %d [%d,%d) exceeds device size %d",
				ErrMalformed, i, start, end, deviceSize)
		}
		parts = append(parts, Partition{
			Index:       i,
			Scheme:      SchemeMBR,
			StartOffset: start,
			Length:      length,
			MBRType:     ptype,
		})
	}
	return parts, nil
}

// ByIndex returns the populated partition at slot index (0-based). It mirrors
// the existing callers' partIndex>=0 path. For GPT, index matches the entry
// slot (empty slots are skipped, so a requested empty/out-of-range slot
// yields [ErrNotFound]). For MBR, index is the 0..3 slot.
func ByIndex(r io.ReaderAt, deviceSize int64, index int) (Partition, error) {
	parts, err := List(r, deviceSize)
	if err != nil {
		return Partition{}, err
	}
	for _, p := range parts {
		if p.Index == index {
			return p, nil
		}
	}
	return Partition{}, fmt.Errorf("%w: index %d", ErrNotFound, index)
}

// ByType returns the first populated GPT partition whose TypeGUID equals
// want. It is the auto-select path used by drivers that look for "the Linux
// filesystem" or "the Apple_APFS" partition regardless of slot.
func ByType(r io.ReaderAt, deviceSize int64, want [16]byte) (Partition, error) {
	parts, err := List(r, deviceSize)
	if err != nil {
		return Partition{}, err
	}
	for _, p := range parts {
		if p.TypeGUID == want {
			return p, nil
		}
	}
	return Partition{}, fmt.Errorf("%w: type %x", ErrNotFound, want)
}

// First returns the first populated partition of any scheme/type. It is the
// "just give me the data partition" convenience matching the callers that
// auto-select the first non-empty entry (zfs/exfat/fat32 style).
func First(r io.ReaderAt, deviceSize int64) (Partition, error) {
	parts, err := List(r, deviceSize)
	if err != nil {
		return Partition{}, err
	}
	if len(parts) == 0 {
		return Partition{}, fmt.Errorf("%w: no populated partition", ErrNotFound)
	}
	return parts[0], nil
}

// mul64 multiplies two non-negative int64 values, reporting ok=false on
// overflow. Inputs are assumed >= 0 (offsets/sizes); a negative input makes
// ok=false.
func mul64(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	if a == 0 || b == 0 {
		return 0, true
	}
	p := a * b
	if p/b != a {
		return 0, false
	}
	return p, true
}

// add64 adds two non-negative int64 values, reporting ok=false on overflow.
func add64(a, b int64) (int64, bool) {
	if a < 0 || b < 0 {
		return 0, false
	}
	s := a + b
	if s < a {
		return 0, false
	}
	return s, true
}
