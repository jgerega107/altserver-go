package apple

import (
	"altserver.local/altserver/internal/anisette"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"howett.net/plist"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixtureAnisette struct{}

func (fixtureAnisette) Fetch(context.Context) (anisette.Data, error) {
	return anisette.Data{"machineID": "fixture-machine", "oneTimePassword": "fixture-otp", "localUserID": "fixture-user", "routingInfo": "17106176", "deviceUniqueIdentifier": "fixture-id", "deviceDescription": "fixture-client", "date": "2026-09-27T12:00:00Z", "locale": "en_US", "timeZone": "UTC", "deviceSerialNumber": "fixture-serial"}, nil
}
func TestLoginTrustedDeviceFlow(t *testing.T) {
	const user = "fixture@example.invalid"
	const password = "fixture-password"
	var srpKey, A []byte
	var verified bool
	var initCount int
	salt := []byte("fixed-salt-for-test")
	sessionKey := bytes.Repeat([]byte{7}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		send := func(v any) {
			b, e := plist.Marshal(v, plist.XMLFormat)
			if e != nil {
				t.Error(e)
			}
			w.Write(b)
		}
		if r.URL.Path == "/verify" || r.URL.Path == "/validate" {
			if r.Header.Get("X-Apple-Identity-Token") == "" {
				t.Error("missing identity token")
			}
			if r.URL.Path == "/validate" {
				if r.Header.Get("security-code") != "123456" {
					t.Error("wrong code")
				}
				verified = true
			} else {
				w.Write([]byte("Verification requested"))
				return
			}
			send(map[string]any{"ec": 0})
			return
		}
		var envelope map[string]any
		body, _ := io.ReadAll(r.Body)
		if _, e := plist.Unmarshal(body, &envelope); e != nil {
			t.Error(e)
			http.Error(w, "bad", 400)
			return
		}
		req := dict(envelope["Request"])
		response := map[string]any{"Status": map[string]any{"ec": 0}}
		switch req["o"] {
		case "init":
			initCount++
			A = data(req["A2k"])
			client := &srpClient{a: big.NewInt(1), A: new(big.Int).SetBytes(A)}
			b := big.NewInt(987654321)
			gB := new(big.Int).Exp(srpG, b, srpN)
			if err := client.challenge(user, password, salt, gB.Bytes(), 1000, "s2k"); err != nil {
				t.Error(err)
			}
			// Independent server side of the exchange, using the same RFC group.
			passwordHash := digest([]byte(password))
			derived := deriveTestPassword(passwordHash, salt)
			x := new(big.Int).SetBytes(digest(salt, digest([]byte(":"), derived)))
			v := new(big.Int).Exp(srpG, x, srpN)
			k := new(big.Int).SetBytes(digest(padded(srpN), padded(srpG)))
			B := new(big.Int).Add(new(big.Int).Mul(k, v), gB)
			B.Mod(B, srpN)
			u := new(big.Int).SetBytes(digest(A, padded(B)))
			base := new(big.Int).Mul(new(big.Int).SetBytes(A), new(big.Int).Exp(v, u, srpN))
			base.Mod(base, srpN)
			secret := new(big.Int).Exp(base, b, srpN)
			srpKey = digest(secret.Bytes())
			response["B"] = padded(B)
			response["s"] = salt
			response["i"] = 1000
			response["sp"] = "s2k"
			response["c"] = "challenge"
		case "complete":
			response["M2"] = digest(new(big.Int).SetBytes(A).Bytes(), data(req["M1"]), srpKey)
			plain, _ := plist.Marshal(map[string]any{"adsid": "123", "GsIdmsToken": "idms", "sk": sessionKey, "c": []byte("token-challenge")}, plist.XMLFormat)
			pad := 16 - len(plain)%16
			plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
			block, _ := aes.NewCipher(mac(srpKey, []byte("extra data key:")))
			encrypted := make([]byte, len(plain))
			cipher.NewCBCEncrypter(block, mac(srpKey, []byte("extra data iv:"))[:16]).CryptBlocks(encrypted, plain)
			response["spd"] = encrypted
			transcript := []byte("s2k,s2k_fo||s2k|")
			transcript = binary.LittleEndian.AppendUint32(transcript, uint32(len(encrypted)))
			transcript = append(transcript, encrypted...)
			transcript = append(transcript, '|', '|')
			response["np"] = mac(mac(srpKey, []byte("HMAC key:")), digest(transcript))
			if !verified {
				response["Status"] = map[string]any{"ec": 0, "au": "trustedDeviceSecondaryAuth"}
			}
		case "apptokens":
			plain, _ := plist.Marshal(map[string]any{"t": map[string]any{appTokenID: map[string]any{"token": "developer-token"}}}, plist.XMLFormat)
			block, _ := aes.NewCipher(sessionKey)
			gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
			nonce := bytes.Repeat([]byte{2}, 16)
			et := append([]byte("XYZ"), nonce...)
			response["et"] = append(et, gcm.Seal(nil, nonce, plain, []byte("XYZ"))...)
		default:
			t.Errorf("unexpected auth operation %v", req["o"])
		}
		send(map[string]any{"Response": response})
	}))
	defer server.Close()
	c := New(fixtureAnisette{})
	c.GSA = server.URL
	c.Verify = server.URL + "/verify"
	c.Validate = server.URL + "/validate"
	calls := 0
	s, err := c.Login(context.Background(), user, password, func(context.Context) (string, error) { calls++; return "123456", nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.token != "developer-token" || calls != 1 || initCount != 2 {
		t.Fatalf("wrong login result: calls=%d attempts=%d", calls, initCount)
	}
}
func TestDeveloperTeamTypesAndPrivacy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Apple-GS-Token") != "secret" {
			t.Error("missing token")
		}
		b, _ := plist.Marshal(map[string]any{"resultCode": 0, "teams": []any{map[string]any{"teamId": "FREE", "name": "Personal", "type": "Individual", "memberships": []any{map[string]any{"name": "Free Provisioning"}}}, map[string]any{"teamId": "PAID", "name": "Paid", "type": "Individual", "memberships": []any{map[string]any{"name": "Apple Developer Program"}}}}}, plist.XMLFormat)
		w.Write(b)
	}))
	defer server.Close()
	c := New(fixtureAnisette{})
	c.Developer = server.URL + "/"
	s := &Session{dsid: "id", token: "secret", client: c}
	teams, err := s.Teams(context.Background())
	if err != nil || len(teams) != 2 || !teams[0].Free || teams[1].Free {
		t.Fatalf("teams=%v err=%v", teams, err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "secret password token", 503) }))
	defer bad.Close()
	c.GSA = bad.URL
	_, err = c.auth(context.Background(), map[string]any{}, anisette.Data{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("error leaked response contents")
	}
}
