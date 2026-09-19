package transportrecovery

import (
	"bytes"
	"testing"
)

func TestIndexDeterministicRoundTrip(t *testing.T) {
	index := Index{Version: MemberIndexVersion, Members: []Member{
		{BatchID: "20260915T000001.000000000Z-0000000000000001", RecordCount: 2, ManifestBytes: 100, ManifestSHA256: "11" + repeatHex("00", 31), DataBytes: 200, DataSHA256: "22" + repeatHex("00", 31)},
		{BatchID: "20260915T000002.000000000Z-0000000000000002", RecordCount: 3, ManifestBytes: 110, ManifestSHA256: "33" + repeatHex("00", 31), DataBytes: 300, DataSHA256: "44" + repeatHex("00", 31)},
	}}
	first, err := MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("member index encoding is not deterministic")
	}
	decoded, err := UnmarshalIndex(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Members) != 2 || decoded.Members[1].BatchID != index.Members[1].BatchID {
		t.Fatal("member index round trip failed")
	}
}
