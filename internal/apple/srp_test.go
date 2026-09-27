package apple

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestSRPIndependentVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/srp.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Protocol, Username, Password, Salt, A, B, M1, M2, K string
		Private                                             string `json:"a"`
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Protocol, func(t *testing.T) {
			decode := func(s string) []byte {
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			a := new(big.Int).SetBytes(decode(v.Private))
			s := &srpClient{a: a, A: new(big.Int).Exp(srpG, a, srpN)}
			if !bytes.Equal(s.A.Bytes(), decode(v.A)) {
				t.Fatal("public key differs from pysrp")
			}
			if err = s.challenge(v.Username, v.Password, decode(v.Salt), decode(v.B), 1000, v.Protocol); err != nil {
				t.Fatal(err)
			}
			for name, pair := range map[string][2][]byte{"M1": {s.proof, decode(v.M1)}, "M2": {s.serverProof, decode(v.M2)}, "K": {s.key, decode(v.K)}} {
				if !bytes.Equal(pair[0], pair[1]) {
					t.Fatalf("%s differs from independent pysrp fixture", name)
				}
			}
		})
	}
}
func TestRejectInvalidSRP(t *testing.T) {
	s, err := newSRP()
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{nil, {0}, srpN.Bytes(), make([]byte, 257)} {
		if s.challenge("u", "p", []byte{1}, b, 10, "s2k") == nil {
			t.Fatal("accepted invalid server public key")
		}
	}
	if s.challenge("u", "p", []byte{1}, []byte{2}, 1000001, "s2k") == nil {
		t.Fatal("accepted unbounded work factor")
	}
}
func TestTokenAuthentication(t *testing.T) {
	key := bytes.Repeat([]byte{42}, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	nonce := bytes.Repeat([]byte{1}, 16)
	envelope := append([]byte("XYZ"), nonce...)
	envelope = append(envelope, gcm.Seal(nil, nonce, []byte("token"), []byte("XYZ"))...)
	plain, err := decryptToken(key, envelope)
	if err != nil || string(plain) != "token" {
		t.Fatal(err)
	}
	envelope[len(envelope)-1] ^= 1
	if _, err = decryptToken(key, envelope); err == nil {
		t.Fatal("accepted forged token")
	}
}
func TestCBCRejectsBadPadding(t *testing.T) {
	if _, err := decryptCBC(make([]byte, 32), make([]byte, 15)); err == nil {
		t.Fatal("accepted partial block")
	}
	key := make([]byte, 32)
	block, _ := aes.NewCipher(mac(key, []byte("extra data key:")))
	plain := bytes.Repeat([]byte{17}, 16)
	cipher.NewCBCEncrypter(block, mac(key, []byte("extra data iv:"))[:16]).CryptBlocks(plain, plain)
	if _, err := decryptCBC(key, plain); err == nil {
		t.Fatal("accepted bad padding")
	}
}
