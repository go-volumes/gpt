# gpt

[![Go Reference](https://pkg.go.dev/badge/github.com/go-volumes/gpt.svg)](https://pkg.go.dev/github.com/go-volumes/gpt)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![CI](https://github.com/go-volumes/gpt/actions/workflows/ci.yml/badge.svg)](https://github.com/go-volumes/gpt/actions/workflows/ci.yml)

A hardened **GPT / MBR partition-table parser** in pure Go (`CGO_ENABLED=0`,
stdlib-only).

`gpt` is the single, neutral partition-table reader for the
[go-volumes](https://github.com/go-volumes) block stack — shared by the
go-filesystems drivers and (later) go-bootloaders, replacing the duplicated and
individually buggy copies those projects used to carry.

It parses **untrusted** on-disk images, so every length, count, and offset is
validated before use: the partition-entry size and count are capped, the
entry-array LBA and every partition's start and length are checked against the
device size, all offset arithmetic is done in `int64` to reject overflow, and a
truncated or short header returns an error instead of panicking. It never
auto-follows nonsensical geometry.

512-byte logical sectors are assumed (matching `hdiutil`, `mkfs`, `newfs_*`,
and `parted` defaults); 4Kn images are out of scope.

## Usage

```go
import "github.com/go-volumes/gpt"

// r is any io.ReaderAt over the raw device/image; deviceSize is its length.
parts, err := gpt.List(r, deviceSize)
if err != nil {
    return err // errors.Is(err, gpt.ErrGPT)
}
for _, p := range parts {
    fmt.Printf("[%d] %s %q start=%d len=%d\n",
        p.Index, p.Scheme, p.Name, p.StartOffset, p.Length)
}

// Convenience selectors:
p, err := gpt.First(r, deviceSize)
p, err = gpt.ByIndex(r, deviceSize, 0)
p, err = gpt.ByType(r, deviceSize, gpt.LinuxFilesystemGUID)
```
