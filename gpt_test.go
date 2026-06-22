package gpt

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"unicode/utf16"
)

// --- image builders -------------------------------------------------------

// gptImage builds an in-memory disk image with a protective MBR, a GPT header
// at LBA 1, and an entry array. entries are written verbatim at entryLBA.
type gptBuilder struct {
	deviceSize int64
	entryLBA   uint64
	numParts   uint32
	entrySize  uint32
	headerLBA  int64 // LBA where "EFI PART" header is written (default 1)
	noHeader   bool
	protectMBR bool
	entries    []byte
}

func newGPT() *gptBuilder {
	return &gptBuilder{
		deviceSize: 64 * 1024 * 1024,
		entryLBA:   2,
		numParts:   4,
		entrySize:  128,
		headerLBA:  1,
		protectMBR: true,
	}
}

func (b *gptBuilder) build() byteReaderAt {
	img := make([]byte, b.deviceSize)
	if b.protectMBR {
		img[510] = 0x55
		img[511] = 0xAA
		// protective MBR entry: type 0xEE
		img[446+4] = 0xEE
		binary.LittleEndian.PutUint32(img[446+8:], 1)
		binary.LittleEndian.PutUint32(img[446+12:], 0xFFFFFFFF)
	}
	if !b.noHeader {
		hoff := b.headerLBA * SectorSize
		if hoff+92 <= int64(len(img)) {
			copy(img[hoff:], []byte("EFI PART"))
			binary.LittleEndian.PutUint64(img[hoff+72:], b.entryLBA)
			binary.LittleEndian.PutUint32(img[hoff+80:], b.numParts)
			binary.LittleEndian.PutUint32(img[hoff+84:], b.entrySize)
		}
	}
	toff := int64(b.entryLBA) * SectorSize
	if toff >= 0 && toff+int64(len(b.entries)) <= int64(len(img)) {
		copy(img[toff:], b.entries)
	}
	return byteReaderAt(img)
}

// gptEntry builds one entry of entrySize bytes.
func gptEntry(entrySize uint32, typeGUID [16]byte, startLBA, endLBA uint64, name string) []byte {
	e := make([]byte, entrySize)
	copy(e[0:16], typeGUID[:])
	binary.LittleEndian.PutUint64(e[32:], startLBA)
	binary.LittleEndian.PutUint64(e[40:], endLBA)
	u := utf16.Encode([]rune(name))
	for i, c := range u {
		if 56+i*2+2 > int(entrySize) {
			break
		}
		binary.LittleEndian.PutUint16(e[56+i*2:], c)
	}
	return e
}

func mbrImage(deviceSize int64, fill func(table []byte)) byteReaderAt {
	img := make([]byte, deviceSize)
	img[510] = 0x55
	img[511] = 0xAA
	fill(img[446 : 446+64])
	return byteReaderAt(img)
}

func mbrEntry(table []byte, slot int, ptype byte, startLBA, numSectors uint32) {
	e := table[slot*16 : slot*16+16]
	e[4] = ptype
	binary.LittleEndian.PutUint32(e[8:], startLBA)
	binary.LittleEndian.PutUint32(e[12:], numSectors)
}

type byteReaderAt []byte

func (b byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b)) {
		return 0, errors.New("EOF")
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, errors.New("short")
	}
	return n, nil
}

// --- tests ----------------------------------------------------------------

func TestListGPT_Valid(t *testing.T) {
	b := newGPT()
	b.numParts = 4
	b.entries = nil
	// slot 0 empty, slot 1 Linux, slot 2 APFS, slot 3 empty
	b.entries = append(b.entries, make([]byte, b.entrySize)...) // empty
	b.entries = append(b.entries, gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, 4095, "data")...)
	b.entries = append(b.entries, gptEntry(b.entrySize, AppleAPFSGUID, 4096, 8191, "apfs")...)
	b.entries = append(b.entries, make([]byte, b.entrySize)...) // empty
	img := b.build()

	parts, err := List(img, b.deviceSize)
	if err != nil {
		t.Fatalf("List err: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2", len(parts))
	}
	if parts[0].Index != 1 || parts[0].StartOffset != 2048*SectorSize {
		t.Fatalf("part0 = %+v", parts[0])
	}
	if parts[0].Length != (4095-2048+1)*SectorSize {
		t.Fatalf("part0 length = %d", parts[0].Length)
	}
	if parts[0].Name != "data" {
		t.Fatalf("part0 name = %q", parts[0].Name)
	}
	if parts[0].Scheme != SchemeGPT || parts[0].Scheme.String() != "GPT" {
		t.Fatalf("scheme = %v", parts[0].Scheme)
	}

	// ByType auto-select
	p, err := ByType(img, b.deviceSize, AppleAPFSGUID)
	if err != nil || p.Index != 2 {
		t.Fatalf("ByType APFS: %+v err %v", p, err)
	}
	// ByIndex
	p, err = ByIndex(img, b.deviceSize, 2)
	if err != nil || p.Name != "apfs" {
		t.Fatalf("ByIndex 2: %+v err %v", p, err)
	}
	// First
	p, err = First(img, b.deviceSize)
	if err != nil || p.Index != 1 {
		t.Fatalf("First: %+v err %v", p, err)
	}
}

func TestListGPT_HardeningVectors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*gptBuilder)
		want   error
	}{
		{"entrySize=0xFFFFFFFF", func(b *gptBuilder) { b.entrySize = 0xFFFFFFFF }, ErrMalformed},
		{"entrySize too small", func(b *gptBuilder) { b.entrySize = 64 }, ErrMalformed},
		{"entrySize zero", func(b *gptBuilder) { b.entrySize = 0 }, ErrMalformed},
		{"numParts=0xFFFFFFFF", func(b *gptBuilder) { b.numParts = 0xFFFFFFFF }, ErrMalformed},
		{"numParts zero", func(b *gptBuilder) { b.numParts = 0 }, ErrMalformed},
		{"entryLBA zero", func(b *gptBuilder) { b.entryLBA = 0 }, ErrMalformed},
		{"entryLBA out of range", func(b *gptBuilder) { b.entryLBA = 0x7FFFFFFFFFFFFFFF }, ErrMalformed},
		{"entry array exceeds device", func(b *gptBuilder) { b.numParts = 256; b.entryLBA = uint64(b.deviceSize/SectorSize) - 1 }, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newGPT()
			tc.mutate(b)
			img := b.build()
			_, err := List(img, b.deviceSize)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestListGPT_PartitionOutOfRange(t *testing.T) {
	// start LBA beyond device
	b := newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, uint64(b.deviceSize/SectorSize)+10, uint64(b.deviceSize/SectorSize)+20, "x")
	if _, err := List(b.build(), b.deviceSize); !errors.Is(err, ErrMalformed) {
		t.Fatalf("start OOR err = %v", err)
	}

	// end beyond device
	b = newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, uint64(b.deviceSize/SectorSize)+100, "x")
	if _, err := List(b.build(), b.deviceSize); !errors.Is(err, ErrMalformed) {
		t.Fatalf("end OOR err = %v", err)
	}

	// startLBA so large that *512 overflows int64
	b = newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, math.MaxUint64, math.MaxUint64, "x")
	if _, err := List(b.build(), b.deviceSize); !errors.Is(err, ErrMalformed) {
		t.Fatalf("start overflow err = %v", err)
	}
}

func TestListGPT_LengthOverflow(t *testing.T) {
	// Case 1: endLBA-startLBA+1 overflows int64 (the add64 sectors branch).
	b := newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 1, math.MaxUint64-1, "x")
	if _, err := List(b.build(), b.deviceSize); !errors.Is(err, ErrMalformed) {
		t.Fatalf("sector-count overflow err = %v", err)
	}

	// Case 2: sectors is a valid positive int64 but sectors*512 overflows
	// int64 (the mul64 byte-length branch). Use a huge device so the start
	// LBA validates, start=0, and end ≈ MaxInt64/256 so +1 stays positive but
	// *512 wraps.
	b = newGPT()
	b.deviceSize = math.MaxInt64
	b.numParts = 1
	b.entryLBA = 2
	end := uint64(math.MaxInt64/256) + 10
	entry := gptEntry(b.entrySize, LinuxFilesystemGUID, 0, end, "y")
	// Build a small backing image (we don't need MaxInt64 bytes of storage);
	// only the header + one entry need to be readable.
	img := make([]byte, 4*SectorSize)
	copy(img[SectorSize:], []byte("EFI PART"))
	binary.LittleEndian.PutUint64(img[SectorSize+72:], b.entryLBA)
	binary.LittleEndian.PutUint32(img[SectorSize+80:], b.numParts)
	binary.LittleEndian.PutUint32(img[SectorSize+84:], b.entrySize)
	copy(img[2*SectorSize:], entry)
	if _, err := List(byteReaderAt(img), b.deviceSize); !errors.Is(err, ErrMalformed) {
		t.Fatalf("byte-length overflow err = %v", err)
	}
}

func TestListGPT_ZeroEndLBA(t *testing.T) {
	// endLBA < startLBA → length stays 0, partition still valid
	b := newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, 0, "z")
	parts, err := List(b.build(), b.deviceSize)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 1 || parts[0].Length != 0 {
		t.Fatalf("parts = %+v", parts)
	}
}

func TestListGPT_TruncatedEntryArray(t *testing.T) {
	// numParts claims 4 but the device is only big enough for the array start;
	// reading an entry beyond EOF breaks the loop, returning earlier parts.
	b := newGPT()
	b.deviceSize = 4 * SectorSize // tiny: header at LBA1, entries at LBA2
	b.entryLBA = 2
	b.numParts = 4
	b.entrySize = 128
	// one valid entry then the array runs off the end of the device
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2, 3, "t")
	// entry array byte-extent: 4*128=512 = 1 sector starting at LBA2 → ends LBA3,
	// device is 4 sectors so the extent fits; but reads of entries 1..3 land in
	// zeroed region (empty slots), fine. Make device just big enough.
	parts, err := List(b.build(), b.deviceSize)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("got %d parts", len(parts))
	}
}

func TestListGPT_TruncatedEntryRead(t *testing.T) {
	// Force a ReadAt failure mid-array via a short backing reader.
	b := newGPT()
	b.numParts = 4
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, 4095, "ok")
	img := b.build()
	// Truncate so entry slot 1 onward cannot be read, but the entry-array
	// extent validation still passes because we keep deviceSize as declared.
	cut := int64(b.entryLBA)*SectorSize + int64(b.entrySize) // only slot 0 present
	short := byteReaderAt(img[:cut])
	parts, err := List(short, b.deviceSize)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 1 || parts[0].Name != "ok" {
		t.Fatalf("parts = %+v", parts)
	}
}

func TestListGPT_TruncatedHeader(t *testing.T) {
	// "EFI PART" present at LBA1 but the 92-byte header can't be fully read.
	img := make([]byte, SectorSize+8)
	copy(img[SectorSize:], []byte("EFI PART"))
	_, err := List(byteReaderAt(img), 1<<20)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestListMBR_Valid(t *testing.T) {
	dev := int64(64 * 1024 * 1024)
	img := mbrImage(dev, func(t []byte) {
		mbrEntry(t, 0, 0x83, 2048, 1000) // Linux
		mbrEntry(t, 1, 0x07, 4096, 2000) // NTFS
	})
	parts, err := List(img, dev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("got %d parts", len(parts))
	}
	if parts[0].MBRType != 0x83 || parts[0].StartOffset != 2048*SectorSize {
		t.Fatalf("part0 = %+v", parts[0])
	}
	if parts[0].Length != 1000*SectorSize || parts[0].Scheme != SchemeMBR {
		t.Fatalf("part0 = %+v", parts[0])
	}
	if parts[0].Scheme.String() != "MBR" {
		t.Fatalf("scheme str = %q", parts[0].Scheme.String())
	}
}

func TestListMBR_Hardening(t *testing.T) {
	dev := int64(1 * 1024 * 1024)
	// start LBA beyond device
	img := mbrImage(dev, func(t []byte) { mbrEntry(t, 0, 0x83, uint32(dev/SectorSize)+10, 5) })
	if _, err := List(img, dev); !errors.Is(err, ErrMalformed) {
		t.Fatalf("start OOR err = %v", err)
	}
	// numSectors runs off the end
	img = mbrImage(dev, func(t []byte) { mbrEntry(t, 0, 0x83, 100, 0xFFFFFFFF) })
	if _, err := List(img, dev); !errors.Is(err, ErrMalformed) {
		t.Fatalf("len OOR err = %v", err)
	}
}

func TestProtectiveMBRFollowsGPT(t *testing.T) {
	// build() writes both a protective MBR (single 0xEE) AND a GPT.
	b := newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, 4095, "g")
	img := b.build()
	parts, err := List(img, b.deviceSize)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 1 || parts[0].Scheme != SchemeGPT {
		t.Fatalf("expected GPT follow, got %+v", parts)
	}
}

func TestProtectiveMBRButNoGPTHeader(t *testing.T) {
	// Single 0xEE MBR entry but no "EFI PART" at LBA1 → returns the MBR part.
	dev := int64(1 * 1024 * 1024)
	img := mbrImage(dev, func(t []byte) { mbrEntry(t, 0, 0xEE, 1, 100) })
	parts, err := List(img, dev)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(parts) != 1 || parts[0].MBRType != 0xEE {
		t.Fatalf("parts = %+v", parts)
	}
}

func TestNoTable(t *testing.T) {
	img := make([]byte, 4096) // no GPT sig, no 0x55AA
	_, err := List(byteReaderAt(img), 4096)
	if !errors.Is(err, ErrNoTable) {
		t.Fatalf("err = %v, want ErrNoTable", err)
	}
}

func TestListErrors(t *testing.T) {
	if _, err := List(nil, 100); !errors.Is(err, ErrMalformed) {
		t.Fatalf("nil reader err = %v", err)
	}
	img := byteReaderAt(make([]byte, 1024))
	if _, err := List(img, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero device err = %v", err)
	}
	if _, err := List(img, -1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("neg device err = %v", err)
	}
}

func TestNotFound(t *testing.T) {
	b := newGPT()
	b.numParts = 1
	b.entries = gptEntry(b.entrySize, LinuxFilesystemGUID, 2048, 4095, "x")
	img := b.build()
	if _, err := ByIndex(img, b.deviceSize, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ByIndex notfound err = %v", err)
	}
	if _, err := ByType(img, b.deviceSize, AppleAPFSGUID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ByType notfound err = %v", err)
	}
	// First on a table with only empty slots → ErrNotFound
	b2 := newGPT()
	b2.numParts = 2
	b2.entries = make([]byte, 2*b2.entrySize) // all empty
	if _, err := First(b2.build(), b2.deviceSize); !errors.Is(err, ErrNotFound) {
		t.Fatalf("First empty err = %v", err)
	}
}

// propagation of List errors through ByIndex/ByType/First
func TestConvenienceErrorPropagation(t *testing.T) {
	img := byteReaderAt(make([]byte, 4096)) // no table
	if _, err := ByIndex(img, 4096, 0); !errors.Is(err, ErrNoTable) {
		t.Fatalf("ByIndex err = %v", err)
	}
	if _, err := ByType(img, 4096, LinuxFilesystemGUID); !errors.Is(err, ErrNoTable) {
		t.Fatalf("ByType err = %v", err)
	}
	if _, err := First(img, 4096); !errors.Is(err, ErrNoTable) {
		t.Fatalf("First err = %v", err)
	}
}

func TestSchemeStringDefault(t *testing.T) {
	if got := Scheme(42).String(); got != "Scheme(42)" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeUTF16Name_ShortEntry(t *testing.T) {
	// Exercise the name decoder with an entry shorter than nameOff and a
	// name region shorter than 72 bytes.
	if got := decodeUTF16Name(make([]byte, 10), 10); got != "" {
		t.Fatalf("short entry name = %q", got)
	}
	// entrySize between nameOff and nameOff+nameMax
	buf := make([]byte, 60)
	binary.LittleEndian.PutUint16(buf[56:], uint16('H'))
	if got := decodeUTF16Name(buf, 60); got != "H" {
		t.Fatalf("clamped name = %q", got)
	}
	// buf shorter than computed end
	if got := decodeUTF16Name(make([]byte, 57), 128); got != "" {
		t.Fatalf("buf-clamped name = %q", got)
	}
}

// failAtReader serves bytes normally except for a read at failOff, which
// errors. Used to force the MBR-table read to fail while the signature reads
// at 510 and the GPT-sig probe at 512 still succeed.
type failAtReader struct {
	data    []byte
	failOff int64
}

func (r failAtReader) ReadAt(p []byte, off int64) (int, error) {
	if off == r.failOff {
		return 0, errors.New("injected read failure")
	}
	if off < 0 || off >= int64(len(r.data)) {
		return 0, errors.New("EOF")
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, errors.New("short")
	}
	return n, nil
}

func TestReadMBRError(t *testing.T) {
	// 0x55AA present (and no EFI PART at 512) but the 64-byte table read at
	// offset 446 is forced to fail.
	img := make([]byte, 1024)
	img[510] = 0x55
	img[511] = 0xAA
	r := failAtReader{data: img, failOff: 446}
	if _, err := List(r, 1<<20); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestArithHelpers(t *testing.T) {
	if _, ok := mul64(-1, 2); ok {
		t.Fatal("mul64 negative should fail")
	}
	if _, ok := mul64(2, -1); ok {
		t.Fatal("mul64 negative b should fail")
	}
	if v, ok := mul64(0, 5); !ok || v != 0 {
		t.Fatal("mul64 zero")
	}
	if _, ok := mul64(math.MaxInt64, 2); ok {
		t.Fatal("mul64 overflow should fail")
	}
	if _, ok := add64(-1, 1); ok {
		t.Fatal("add64 negative should fail")
	}
	if _, ok := add64(1, -1); ok {
		t.Fatal("add64 negative b should fail")
	}
	if _, ok := add64(math.MaxInt64, 1); ok {
		t.Fatal("add64 overflow should fail")
	}
}

// FuzzList asserts the parser never panics on arbitrary input.
func FuzzList(f *testing.F) {
	f.Add([]byte(newGPT().build()), int64(64*1024*1024))
	// malformed seeds
	bad := newGPT()
	bad.entrySize = 0xFFFFFFFF
	f.Add([]byte(bad.build()), int64(64*1024*1024))
	bad2 := newGPT()
	bad2.numParts = 0xFFFFFFFF
	f.Add([]byte(bad2.build()), int64(64*1024*1024))
	f.Add([]byte("EFI PART truncated header...."), int64(1<<20))
	mbr := make([]byte, 512)
	mbr[510] = 0x55
	mbr[511] = 0xAA
	f.Add(mbr, int64(1<<20))
	f.Add([]byte{}, int64(0))
	f.Add(make([]byte, 1024), int64(-1))

	f.Fuzz(func(t *testing.T, img []byte, deviceSize int64) {
		// Bound the mutated image so the fuzzing engine's shared-memory cap
		// isn't exceeded; we are exercising the parser's validation logic,
		// not its ability to hold gigantic buffers.
		if len(img) > 1<<20 {
			img = img[:1<<20]
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("List panicked: %v", r)
			}
		}()
		parts, err := List(byteReaderAt(img), deviceSize)
		if err != nil {
			return
		}
		// Every returned partition must be in-range — the whole point.
		for _, p := range parts {
			if p.StartOffset < 0 || p.Length < 0 {
				t.Fatalf("negative geometry: %+v", p)
			}
			if p.StartOffset+p.Length > deviceSize {
				t.Fatalf("partition exceeds device: %+v (dev=%d)", p, deviceSize)
			}
		}
	})
}
