package ids

import (
	"bytes"
	"testing"
)

func TestUUIDv7(t *testing.T) {
	id1, err := NewUUIDv7()
	if err != nil {
		t.Fatalf("failed to generate UUIDv7: %v", err)
	}
	id2, err := NewUUIDv7()
	if err != nil {
		t.Fatalf("failed to generate UUIDv7: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique IDs, got duplicate %v", id1)
	}
	if id1.Version() != 7 {
		t.Errorf("expected version 7, got %d", id1.Version())
	}
}

func TestRandomBase64URL(t *testing.T) {
	str1, err := RandomBase64URL(32)
	if err != nil {
		t.Fatalf("failed to generate random base64url: %v", err)
	}
	str2, err := RandomBase64URL(32)
	if err != nil {
		t.Fatalf("failed to generate random base64url: %v", err)
	}
	if str1 == str2 {
		t.Fatalf("expected unique strings, got duplicates: %v", str1)
	}
	if len(str1) < 40 {
		t.Errorf("expected length >= 40 for 32 bytes base64url, got %d", len(str1))
	}
}

func TestSHA256AndConstantTimeCompare(t *testing.T) {
	val := "secret-code-value"
	digest1 := SHA256DigestString(val)
	digest2 := SHA256DigestString(val)
	digest3 := SHA256DigestString("other-value")

	if !bytes.Equal(digest1, digest2) {
		t.Error("expected equal hashes for same string")
	}
	if !ConstantTimeCompare(digest1, digest2) {
		t.Error("expected constant-time match")
	}
	if ConstantTimeCompare(digest1, digest3) {
		t.Error("expected constant-time mismatch")
	}
}
