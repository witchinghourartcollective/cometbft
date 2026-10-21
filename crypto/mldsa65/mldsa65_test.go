package mldsa65_test

import (
	"testing"

	"github.com/cometbft/cometbft/crypto/encoding"
	. "github.com/cometbft/cometbft/crypto/mldsa65"
)

func TestSignVerify(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()

	msg := []byte("hour-chain consensus vote")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), SignatureSize)
	}
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if pub.VerifySignature([]byte("different message"), sig) {
		t.Fatal("signature verified against the wrong message")
	}
}

func TestProtoRoundTrip(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()

	proto, err := encoding.PubKeyToProto(pub)
	if err != nil {
		t.Fatalf("PubKeyToProto failed: %v", err)
	}
	if proto.GetMlDsa65() == nil {
		t.Fatal("expected PublicKey_MlDsa65 in proto oneof, got something else")
	}

	back, err := encoding.PubKeyFromProto(proto)
	if err != nil {
		t.Fatalf("PubKeyFromProto failed: %v", err)
	}
	if !pub.Equals(back) {
		t.Fatal("round-tripped pubkey does not equal original")
	}
}

func TestPubKeyFromTypeAndBytes(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()

	back, err := encoding.PubKeyFromTypeAndBytes(KeyType, pub.Bytes())
	if err != nil {
		t.Fatalf("PubKeyFromTypeAndBytes failed: %v", err)
	}
	if !pub.Equals(back) {
		t.Fatal("pubkey round-tripped via type+bytes does not equal original")
	}
}

func TestMarshalUnmarshalWire(t *testing.T) {
	priv := GenPrivKey()
	pub := priv.PubKey()

	proto, err := encoding.PubKeyToProto(pub)
	if err != nil {
		t.Fatalf("PubKeyToProto failed: %v", err)
	}

	wire, err := proto.Marshal()
	if err != nil {
		t.Fatalf("proto Marshal failed: %v", err)
	}

	var decoded = proto
	decoded.Sum = nil
	if err := decoded.Unmarshal(wire); err != nil {
		t.Fatalf("proto Unmarshal failed: %v", err)
	}
	if decoded.GetMlDsa65() == nil {
		t.Fatal("unmarshaled proto missing mldsa65 field")
	}

	back, err := encoding.PubKeyFromProto(decoded)
	if err != nil {
		t.Fatalf("PubKeyFromProto after wire round-trip failed: %v", err)
	}
	if !pub.Equals(back) {
		t.Fatal("pubkey does not survive a real proto wire marshal/unmarshal round-trip")
	}
}
