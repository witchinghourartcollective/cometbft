// Package mldsa65 implements the crypto.PubKey / crypto.PrivKey interfaces
// for FIPS 204 ML-DSA-65 (k=6, l=5), using cloudflare/circl's implementation.
//
// This is part of hOUR Chain's fork toward making ML-DSA an actual CometBFT
// consensus signature type, not just an additive checkpoint attestation --
// see hOUR-Chain's docs/GENESIS-DECISION-GATE.md, "1b. End target: fork
// cometbft + cosmos-sdk crypto codecs". ML-DSA-65 is the same parameter set
// used by hOUR Chain's packages/pqc-checkpoint and packages/pqc-profile, and
// by the account-abstraction fork's PqcAccount -- see
// docs/SIGNATURE-CANONICALIZATION.md for the chain-wide convention.
//
// Signatures are ~52x larger than Ed25519 (3309 vs 64 bytes). This has real
// cost: every vote, commit signature, and proposal signature carries one.
// For a validator set of any meaningful size this multiplies block/commit
// bandwidth substantially -- acceptable for a devnet proving the mechanism,
// not yet evaluated for a production validator set size.
package mldsa65

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

const (
	PrivKeyName = "tendermint/PrivKeyMlDsa65"
	PubKeyName  = "tendermint/PubKeyMlDsa65"

	// PubKeySize is the size, in bytes, of ML-DSA-65 public keys.
	PubKeySize = mldsa65.PublicKeySize
	// PrivateKeySize is the size, in bytes, of ML-DSA-65 private keys
	// (circl's packed representation, not just a seed).
	PrivateKeySize = mldsa65.PrivateKeySize
	// SignatureSize is the size, in bytes, of an ML-DSA-65 signature.
	SignatureSize = mldsa65.SignatureSize
	// SeedSize is the size, in bytes, of the seed GenPrivKeyFromSeed expects.
	SeedSize = mldsa65.SeedSize

	KeyType = "mldsa65"
)

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)
}

var (
	_ crypto.PrivKey = PrivKey{}
	_ crypto.PubKey  = PubKey{}
)

// PrivKey implements crypto.PrivKey. It stores circl's packed private-key
// bytes directly (PrivateKeySize), not a seed -- unlike Ed25519, ML-DSA-65
// private keys are not practically re-derivable from a short seed alone
// without redoing key expansion on every load, so PubKey() below unpacks
// via circl rather than caching a separate pubkey.
type PrivKey []byte

// Bytes returns the privkey byte format.
func (privKey PrivKey) Bytes() []byte {
	return []byte(privKey)
}

// Sign produces an ML-DSA-65 signature on the provided message.
func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	if len(privKey) != PrivateKeySize {
		return nil, fmt.Errorf("mldsa65: privkey has incorrect size %d, want %d", len(privKey), PrivateKeySize)
	}

	var sk mldsa65.PrivateKey
	var buf [PrivateKeySize]byte
	copy(buf[:], privKey)
	sk.Unpack(&buf)

	sig := make([]byte, SignatureSize)
	// ctx (domain-separation context string) left empty: CometBFT's own
	// SignBytes already canonicalizes/domain-separates what gets signed
	// (chain ID, height, etc. are part of the message), so no additional
	// ML-DSA context string is needed here. randomized=false: deterministic
	// signing, matching Ed25519's deterministic behavior in this codebase
	// and avoiding a second source of nondeterminism in consensus signing.
	if err := mldsa65.SignTo(&sk, msg, nil, false, sig); err != nil {
		return nil, fmt.Errorf("mldsa65: sign failed: %w", err)
	}
	return sig, nil
}

// PubKey derives the corresponding public key from the private key.
func (privKey PrivKey) PubKey() crypto.PubKey {
	if len(privKey) != PrivateKeySize {
		panic("mldsa65: privkey has incorrect size")
	}

	var sk mldsa65.PrivateKey
	var buf [PrivateKeySize]byte
	copy(buf[:], privKey)
	sk.Unpack(&buf)

	pk := sk.Public().(*mldsa65.PublicKey)
	return PubKey(pk.Bytes())
}

// Equals runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if o, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], o[:]) == 1
	}
	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

// GenPrivKey generates a new ML-DSA-65 private key using OS randomness via
// cometbft/crypto.CReader(), matching the other key types in this repo.
func GenPrivKey() PrivKey {
	return genPrivKey(crypto.CReader())
}

func genPrivKey(rand io.Reader) PrivKey {
	_, sk, err := mldsa65.GenerateKey(rand)
	if err != nil {
		panic(err)
	}
	return PrivKey(sk.Bytes())
}

// GenPrivKeyFromSeed deterministically derives a key pair from a
// SeedSize-byte seed, e.g. for test fixtures / NIST KAT reproduction.
func GenPrivKeyFromSeed(seed []byte) PrivKey {
	if len(seed) != SeedSize {
		panic("mldsa65: seed has incorrect size")
	}
	var seedBuf [SeedSize]byte
	copy(seedBuf[:], seed)
	_, sk := mldsa65.NewKeyFromSeed(&seedBuf)
	return PrivKey(sk.Bytes())
}

//-------------------------------------

// PubKey implements crypto.PubKey for ML-DSA-65.
type PubKey []byte

// Address is the SHA256-20 of the raw pubkey bytes, same convention as
// every other key type in this repo (truncated hash, not the full key).
func (pubKey PubKey) Address() crypto.Address {
	if len(pubKey) != PubKeySize {
		panic("mldsa65: pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubKey))
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return []byte(pubKey)
}

func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	if len(pubKey) != PubKeySize || len(sig) != SignatureSize {
		return false
	}

	var pk mldsa65.PublicKey
	var buf [PubKeySize]byte
	copy(buf[:], pubKey)
	pk.Unpack(&buf)

	return mldsa65.Verify(&pk, msg, nil, sig)
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyMlDsa65{%X}", []byte(pubKey))
}

func (pubKey PubKey) Type() string {
	return KeyType
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if o, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], o[:])
	}
	return false
}
