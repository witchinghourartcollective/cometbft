package types

import (
	"testing"

	"github.com/cometbft/cometbft/crypto/mldsa65"
)

// TestConsensusParamsAcceptMlDsa65PubKeyType confirms ConsensusParams.ValidateBasic
// accepts "mldsa65" in Validator.PubKeyTypes -- this is the real gate a fresh
// genesis.json's consensus.params.validator.pub_key_types needs to pass
// before an mldsa65-keyed validator can even be considered, independent of
// everything else (proto codec, FilePV) already proven to work.
func TestConsensusParamsAcceptMlDsa65PubKeyType(t *testing.T) {
	params := DefaultConsensusParams()
	params.Validator.PubKeyTypes = []string{ABCIPubKeyTypeMlDsa65}

	if err := params.ValidateBasic(); err != nil {
		t.Fatalf("ValidateBasic rejected mldsa65 pubkey type: %v", err)
	}

	if !IsValidPubkeyType(params.Validator, mldsa65.KeyType) {
		t.Fatal("IsValidPubkeyType returned false for mldsa65")
	}
	if IsValidPubkeyType(params.Validator, "ed25519") {
		t.Fatal("IsValidPubkeyType incorrectly accepted ed25519 when only mldsa65 is listed")
	}
}
