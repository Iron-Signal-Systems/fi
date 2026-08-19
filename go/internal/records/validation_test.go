package records

import (
	"encoding/base64"
	"strings"
	"testing"
)

func utf16b64(s string) string {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0x7f {
			panic("test helper only supports ASCII")
		}
		b = append(b, byte(r), 0)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestValidateStreamInventory(t *testing.T) {
	inventory := StreamInventory{
		State: ObservationStatePresent,
		Streams: []StreamObservation{
			{
				Identity: StreamIdentity{Kind: StreamNamedData, NameUTF16LEBase64URL: utf16b64("payload"), StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64(":payload:$DATA")},
				State:    ObservationStatePresent, LogicalSize: "42", AllocatedSize: "4096",
			},
			{
				Identity: StreamIdentity{Kind: StreamDefaultData, StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64("::$DATA")},
				State:    ObservationStatePresent, LogicalSize: "100", AllocatedSize: "4096",
			},
		},
	}
	// Ordering is by canonical raw-name encoding, so sort for a deterministic test.
	if inventory.Streams[0].Identity.RawNameUTF16LEBase64URL > inventory.Streams[1].Identity.RawNameUTF16LEBase64URL {
		inventory.Streams[0], inventory.Streams[1] = inventory.Streams[1], inventory.Streams[0]
	}
	if err := ValidateStreamInventory(inventory); err != nil {
		t.Fatal(err)
	}
}

func TestValidateStreamInventoryRejectsLeadingZero(t *testing.T) {
	inventory := StreamInventory{State: ObservationStatePresent, Streams: []StreamObservation{{
		Identity: StreamIdentity{Kind: StreamDefaultData, StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64("::$DATA")},
		State:    ObservationStatePresent, LogicalSize: "042", AllocatedSize: "4096",
	}}}
	if err := ValidateStreamInventory(inventory); err == nil || !strings.Contains(err.Error(), "InvalidDecimal") {
		t.Fatalf("error = %v", err)
	}
}
