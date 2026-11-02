package main

import "testing"

func TestWholeBatchGrouping(t *testing.T) {
	b := []batch{{records: 8192, bytes: 12 << 20}, {records: 8192, bytes: 12 << 20}, {records: 8192, bytes: 12 << 20}, {records: 8192, bytes: 12 << 20}, {records: 8192, bytes: 12 << 20}}
	p32 := group(b, 32768, 64<<20)
	p64 := group(b, 65536, 64<<20)
	if p32.groups != 2 || p64.groups != 1 || p32.records != 40960 || p32.oversized != 0 {
		t.Fatalf("groups %#v %#v", p32, p64)
	}
}
func TestByteBudget(t *testing.T) {
	b := []batch{{records: 8192, bytes: 30 << 20}, {records: 8192, bytes: 30 << 20}, {records: 8192, bytes: 30 << 20}}
	if got := group(b, 65536, 50<<20).groups; got != 3 {
		t.Fatalf("groups=%d want=3", got)
	}
}
func TestOversizedSourceBatch(t *testing.T) {
	s := group([]batch{{records: 70000, bytes: 5 << 20}, {records: 100, bytes: 100}}, 65536, 64<<20)
	if s.oversized != 1 || s.groups != 1 {
		t.Fatalf("bad oversized detection %#v", s)
	}
}
