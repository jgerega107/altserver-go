package apple

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
)

// RFC 5054, Appendix A, 2048-bit group. Apple uses SHA-256 and omits the
// username from x, but includes it in M1. See docs/architecture.md.
const modulus = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

var srpN, _ = new(big.Int).SetString(modulus, 16)
var srpG = big.NewInt(2)

type srpClient struct {
	a, A                    *big.Int
	key, proof, serverProof []byte
}

func digest(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func padded(n *big.Int) []byte { return n.FillBytes(make([]byte, 256)) }
func newSRP() (*srpClient, error) {
	a, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		return nil, err
	}
	if a.Sign() == 0 {
		a.SetInt64(1)
	}
	return &srpClient{a: a, A: new(big.Int).Exp(srpG, a, srpN)}, nil
}
func (s *srpClient) challenge(user, password string, salt, B []byte, iterations int, protocol string) error {
	if iterations < 1 || iterations > 1000000 || len(salt) < 1 || len(salt) > 1024 || len(B) > 256 {
		return errors.New("invalid SRP challenge")
	}
	b := new(big.Int).SetBytes(B)
	if b.Sign() == 0 || b.Cmp(srpN) >= 0 {
		return errors.New("invalid SRP server public key")
	}
	pass := digest([]byte(password))
	switch protocol {
	case "s2k":
	case "s2k_fo":
		pass = []byte(hex.EncodeToString(pass))
	default:
		return errors.New("unsupported Apple password protocol")
	}
	derived := pbkdf2.Key(pass, salt, iterations, 32, sha256.New)
	defer clear(derived)
	clear(pass)
	x := new(big.Int).SetBytes(digest(salt, digest([]byte(":"), derived)))
	k := new(big.Int).SetBytes(digest(padded(srpN), padded(srpG)))
	u := new(big.Int).SetBytes(digest(padded(s.A), padded(b)))
	if u.Sign() == 0 {
		return errors.New("invalid SRP scrambling parameter")
	}
	v := new(big.Int).Exp(srpG, x, srpN)
	base := new(big.Int).Sub(b, new(big.Int).Mul(k, v))
	base.Mod(base, srpN)
	exponent := new(big.Int).Add(s.a, new(big.Int).Mul(u, x))
	secret := new(big.Int).Exp(base, exponent, srpN)
	s.key = digest(secret.Bytes())
	hn, hg := digest(padded(srpN)), digest(padded(srpG))
	for i := range hn {
		hn[i] ^= hg[i]
	}
	s.proof = digest(hn, digest([]byte(user)), salt, s.A.Bytes(), b.Bytes(), s.key)
	s.serverProof = digest(s.A.Bytes(), s.proof, s.key)
	return nil
}
func decryptCBC(key, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, errors.New("invalid encrypted login data")
	}
	block, err := aes.NewCipher(mac(key, []byte("extra data key:")))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, mac(key, []byte("extra data iv:"))[:16]).CryptBlocks(out, data)
	padding := int(out[len(out)-1])
	if padding < 1 || padding > 16 || padding > len(out) {
		return nil, errors.New("invalid login padding")
	}
	for _, v := range out[len(out)-padding:] {
		if int(v) != padding {
			return nil, errors.New("invalid login padding")
		}
	}
	return out[:len(out)-padding], nil
}
func decryptToken(key, data []byte) ([]byte, error) {
	if len(data) < 35 || string(data[:3]) != "XYZ" {
		return nil, errors.New("invalid app token envelope")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[3:19], data[19:], data[:3])
}
