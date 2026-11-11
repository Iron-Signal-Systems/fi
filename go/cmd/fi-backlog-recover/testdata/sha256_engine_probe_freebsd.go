//go:build freebsd && cgo

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the FI Source Review License.
//
// Development-only, read-only SHA-256 engine probe over authenticated FI
// cached source batches. This file belongs under testdata so the normal FI
// build and test packages never compile it. No SQL writes or hash bypasses.
package main

/*
#cgo LDFLAGS: -lcrypto
#include <openssl/evp.h>
#include <stddef.h>

static EVP_MD_CTX *fi_probe_sha_new(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return NULL;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}
static int fi_probe_sha_update(EVP_MD_CTX *ctx, const void *p, size_t n) {
    return EVP_DigestUpdate(ctx, p, n);
}
static int fi_probe_sha_final(EVP_MD_CTX *ctx, unsigned char *out) {
    unsigned int n = 0;
    return EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 32;
}
static int fi_probe_sha_sum(const void *p, size_t n, unsigned char *out) {
    unsigned int output = 0;
    return EVP_Digest(p, n, out, &output, EVP_sha256(), NULL) == 1 && output == 32;
}
*/
import "C"

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "sort"
    "time"
    "unsafe"
)

const (
    maxBatchBytes = 64 << 20
    maxTotalBytes = 384 << 20
)

type batchSample struct {
    payload []byte
    rows int
}

type shaStream struct { ctx *C.EVP_MD_CTX }

func newSHAStream() (*shaStream, error) {
    p := C.fi_probe_sha_new()
    if p == nil { return nil, errors.New("OpenSSL EVP_DigestInit_ex failed") }
    return &shaStream{ctx: p}, nil
}
func (s *shaStream) close() {
    if s.ctx != nil { C.EVP_MD_CTX_free(s.ctx); s.ctx = nil }
}
func (s *shaStream) write(b []byte) error {
    if s.ctx == nil { return errors.New("OpenSSL SHA stream closed") }
    if len(b) == 0 { return nil }
    if C.fi_probe_sha_update(s.ctx, unsafe.Pointer(unsafe.SliceData(b)), C.size_t(len(b))) != 1 {
        return errors.New("OpenSSL EVP_DigestUpdate failed")
    }
    runtime.KeepAlive(b)
    return nil
}
func (s *shaStream) sum() ([32]byte, error) {
    var out [32]byte
    if s.ctx == nil { return out, errors.New("OpenSSL SHA stream closed") }
    if C.fi_probe_sha_final(s.ctx, (*C.uchar)(unsafe.Pointer(&out[0]))) != 1 {
        return out, errors.New("OpenSSL EVP_DigestFinal_ex failed")
    }
    return out, nil
}
func opensslSum(b []byte) ([32]byte, error) {
    var out [32]byte
    var p unsafe.Pointer
    if len(b) > 0 { p = unsafe.Pointer(unsafe.SliceData(b)) }
    if C.fi_probe_sha_sum(p, C.size_t(len(b)), (*C.uchar)(unsafe.Pointer(&out[0]))) != 1 {
        return out, errors.New("OpenSSL EVP_Digest failed")
    }
    runtime.KeepAlive(b)
    return out, nil
}

// eachRecord preserves the exact LF-terminated JSONL record boundary. The
// signed batch digest is over the entire concatenated batch, not a Merkle root
// or hash of per-record digests.
func eachRecord(b []byte, f func([]byte) error) (int, error) {
    n := 0
    for len(b) > 0 {
        end := bytes.IndexByte(b, '\n')
        if end < 0 { return n, errors.New("batch lacks final LF") }
        record := b[:end+1]
        if len(record) <= 1 { return n, errors.New("empty LF-terminated record") }
        if err := f(record); err != nil { return n, err }
        b = b[end+1:]
        n++
    }
    return n, nil
}

func loadSamples(root string, offset, count int) ([]batchSample, int64, int, error) {
    names, err := filepath.Glob(filepath.Join(root, "receipt-*", "batch-*.data"))
    if err != nil { return nil, 0, 0, err }
    sort.Strings(names)
    if len(names) != 8399 { return nil, 0, 0, fmt.Errorf("signed cache has %d data batches, expected 8399",len(names)) }
    if offset < 0 || count < 1 || count > 32 || offset+count > len(names) {
        return nil, 0, 0, errors.New("sample offset or count outside verified cache")
    }
    samples := make([]batchSample, 0, count)
    var total int64
    rows := 0
    for _, name := range names[offset:offset+count] {
        info, err := os.Lstat(name)
        if err != nil { return nil, 0, 0, err }
        if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
            info.Size() <= 0 || info.Size() > maxBatchBytes {
            return nil, 0, 0, fmt.Errorf("invalid cached batch size or file type: %s", filepath.Base(name))
        }
        total += info.Size()
        if total > maxTotalBytes { return nil, 0, 0, errors.New("sample memory bound exceeded") }
        b, err := os.ReadFile(name)
        if err != nil { return nil, 0, 0, err }
        if int64(len(b)) != info.Size() { return nil, 0, 0, errors.New("sample file length changed during read") }
        manifestPath := name[:len(name)-len(".data")] + ".manifest"
        rawManifest, err := os.ReadFile(manifestPath)
        if err != nil { return nil, 0, 0, err }
        var manifest struct {
            DataSHA256 string
            RecordCount int
        }
        var document map[string]json.RawMessage
        if err := json.Unmarshal(rawManifest, &document); err != nil { return nil, 0, 0, err }
        if err := json.Unmarshal(document["data_sha256"], &manifest.DataSHA256); err != nil {
            return nil, 0, 0, fmt.Errorf("cached manifest lacks data_sha256: %w", err)
        }
        if err := json.Unmarshal(document["record_count"], &manifest.RecordCount); err != nil {
            return nil, 0, 0, fmt.Errorf("cached manifest lacks record_count: %w", err)
        }
        goHash := sha256.Sum256(b)
        if hex.EncodeToString(goHash[:]) != manifest.DataSHA256 {
            return nil, 0, 0, fmt.Errorf("cached batch does not match manifest SHA: %s",filepath.Base(name))
        }
        opensslHash, err := opensslSum(b)
        if err != nil || goHash != opensslHash { return nil, 0, 0, fmt.Errorf("OpenSSL SHA mismatch: %s, %v",filepath.Base(name),err) }
        n, err := eachRecord(b, func(rec []byte) error {
            a := sha256.Sum256(rec)
            c, err := opensslSum(rec)
            if err != nil || a != c { return errors.New("OpenSSL record digest differs") }
            return nil
        })
        if err != nil { return nil, 0, 0, err }
        if n != manifest.RecordCount { return nil, 0, 0, fmt.Errorf("record count mismatch in %s",filepath.Base(name)) }
        samples = append(samples, batchSample{payload:b,rows:n})
        rows += n
    }
    return samples, total, rows, nil
}

// runBench independently verifies each operation's checksum and processes
// exactly the same payloads with both engines. No PostgreSQL state is used.
func runBench(samples []batchSample, engine string, perRecord bool) (time.Duration, uint64, error) {
    tick := time.Now()
    var checksum uint64
    for _, sample := range samples {
        if perRecord {
            _, err := eachRecord(sample.payload, func(rec []byte) error {
                var sum [32]byte
                var err error
                if engine == "openssl" { sum, err = opensslSum(rec) } else { sum = sha256.Sum256(rec) }
                checksum += uint64(sum[0]) + uint64(sum[1])<<8 + uint64(sum[31])<<16
                return err
            })
            if err != nil { return 0, 0, err }
        } else {
            if engine == "openssl" {
                h, err := newSHAStream()
                if err != nil { return 0, 0, err }
                _, err = eachRecord(sample.payload, h.write)
                if err != nil { h.close(); return 0, 0, err }
                digest, err := h.sum()
                h.close()
                if err != nil { return 0, 0, err }
                checksum += uint64(digest[0]) + uint64(digest[1])<<8 + uint64(digest[31])<<16
            } else {
                h := sha256.New()
                _, err := eachRecord(sample.payload, func(b []byte) error { _, e := h.Write(b); return e })
                if err != nil { return 0, 0, err }
                digest := h.Sum(nil)
                checksum += uint64(digest[0]) + uint64(digest[1])<<8 + uint64(digest[31])<<16
            }
        }
    }
    return time.Since(tick), checksum, nil
}

func main() {
    root := flag.String("cache", "", "exact read-only verified-cache root")
    offset := flag.Int("offset", 175, "first signed batch index, sorted by filename")
    count := flag.Int("count", 16, "number of whole batches (maximum 32)")
    rounds := flag.Int("rounds", 3, "alternating engine comparisons, 1..5")
    flag.Parse()
    if flag.NArg()!=0 || *root=="" || *rounds<1 || *rounds>5 { fmt.Fprintln(os.Stderr,"FI SHA PROBE STOP: invalid arguments");os.Exit(2) }
    info, err := os.Lstat(*root)
    if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { fmt.Fprintln(os.Stderr,"FI SHA PROBE STOP: invalid cache root");os.Exit(1) }
    samples, totalBytes, records, err := loadSamples(*root,*offset,*count)
    if err != nil { fmt.Fprintln(os.Stderr,"FI SHA PROBE STOP:",err); os.Exit(1) }
    fmt.Printf("FI SHA PROBE SOURCE PASS signed_batches=%d sample_bytes=%d sample_records=%d signed_manifest_digests=verified\n",len(samples),totalBytes,records)
    for _, kind := range []string{"batch_stream", "record_sum"} {
        for round:=1;round<=*rounds;round++ {
            engines:=[]string{"go","openssl"}
            if round%2==0 { engines[0],engines[1]=engines[1],engines[0] }
            values:=make(map[string]uint64)
            for _, engine:=range engines {
                d, sum, err := runBench(samples,engine,kind=="record_sum")
                if err!=nil { fmt.Fprintln(os.Stderr,"FI SHA PROBE STOP:",err);os.Exit(1) }
                fmt.Printf("FI SHA PROBE SAMPLE kind=%s round=%d engine=%s elapsed_ms=%.3f bytes=%d records=%d\n",
                    kind,round,engine,float64(d.Microseconds())/1000,totalBytes,records)
                values[engine]=sum
            }
            if values["go"]!=values["openssl"] { fmt.Fprintln(os.Stderr,"FI SHA PROBE STOP: engine checksum differs");os.Exit(1) }
        }
    }
    fmt.Println("FI SHA PROBE ACCEPTED comparison=read_only original_hashes_retained=true no_db_changes=true")
}
