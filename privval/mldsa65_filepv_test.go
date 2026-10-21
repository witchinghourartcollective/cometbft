package privval_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cometbft/cometbft/crypto/mldsa65"
	"github.com/cometbft/cometbft/privval"
)

// TestFilePVWithMlDsa65 confirms privval.NewFilePV (unlike the ed25519-only
// convenience wrapper GenFilePV) already works generically for a non-ed25519
// crypto.PrivKey, including a real JSON save/load round-trip -- this is the
// only piece needed for hourd's own init command to generate an mldsa65
// validator key; no cometbft core patch required beyond what's already
// landed in crypto/mldsa65 (whose init() registers the JSON type names
// FilePV's amino-style (de)serialization depends on).
func TestFilePVWithMlDsa65(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "priv_validator_key.json")
	statePath := filepath.Join(dir, "priv_validator_state.json")

	priv := mldsa65.GenPrivKey()
	pv := privval.NewFilePV(priv, keyPath, statePath)
	pv.Save()

	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not written: %v", err)
	}

	loaded := privval.LoadFilePV(keyPath, statePath)

	origPub, err := pv.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey on original failed: %v", err)
	}
	loadedPub, err := loaded.GetPubKey()
	if err != nil {
		t.Fatalf("GetPubKey on loaded failed: %v", err)
	}

	if loadedPub.Type() != mldsa65.KeyType {
		t.Fatalf("loaded pubkey type = %q, want %q", loadedPub.Type(), mldsa65.KeyType)
	}
	if !origPub.Equals(loadedPub) {
		t.Fatal("loaded FilePV pubkey does not match the original after a real JSON save/load round-trip")
	}

	msg := []byte("test vote bytes")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("sign with original key failed: %v", err)
	}
	if !loadedPub.VerifySignature(msg, sig) {
		t.Fatal("signature from the original key does not verify against the loaded pubkey")
	}
}
