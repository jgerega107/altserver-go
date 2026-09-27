package apple

import (
	"altserver.local/altserver/internal/profile"
	"altserver.local/altserver/internal/state"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Certificate struct {
	DER       []byte
	KeyPEM    []byte
	MachineID string
	Serial    string
}

func (s *Session) RegisterDevice(ctx context.Context, team, udid, name string) error {
	r, err := s.call(ctx, "ios/listDevices.action", team, nil)
	if err != nil {
		return err
	}
	for _, d := range array(r["devices"]) {
		if str(dict(d)["deviceNumber"]) == udid {
			return nil
		}
	}
	_, err = s.call(ctx, "ios/addDevice.action", team, map[string]any{"deviceNumber": udid, "name": name})
	return err
}

// Reuse our own key; never revoke someone else's certificate to free a slot.
func (s *Session) Certificate(ctx context.Context, team string, store *state.Store) (Certificate, error) {
	hash := sha256.Sum256([]byte(s.dsid + ":" + team))
	name := "certificate-" + hex.EncodeToString(hash[:]) + ".json"
	var cert Certificate
	err := store.Read(name, &cert)
	if err == nil {
		parsed, e := x509.ParseCertificate(cert.DER)
		if e == nil && parsed.NotAfter.After(time.Now().Add(time.Hour)) {
			return cert, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return cert, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return cert, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "AltServer Linux", Organization: []string{"AltServer Linux"}}}, key)
	if err != nil {
		return cert, err
	}
	machine := strings.ToUpper(state.UUID())
	r, err := s.call(ctx, "ios/submitDevelopmentCSR.action", team, map[string]any{"csrContent": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "machineId": machine, "machineName": "AltServer Linux"})
	if err != nil {
		return cert, fmt.Errorf("certificate creation failed (existing certificates were not revoked): %w", err)
	}
	der := data(dict(r["certRequest"])["certContent"])
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return cert, fmt.Errorf("Apple returned invalid development certificate")
	}
	public, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.Cmp(key.N) != 0 || public.E != key.E {
		return cert, fmt.Errorf("Apple certificate does not match generated key")
	}
	cert = Certificate{DER: der, KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), MachineID: machine, Serial: strings.ToUpper(parsed.SerialNumber.Text(16))}
	if len(cert.Serial)%2 != 0 {
		cert.Serial = "0" + cert.Serial
	}
	return cert, store.Write(name, cert)
}
func (s *Session) Provision(ctx context.Context, team, bundle, name string, groups []string, certificate Certificate, udid string) (profile.Profile, error) {
	var zero profile.Profile
	r, err := s.call(ctx, "ios/listAppIds.action", team, nil)
	if err != nil {
		return zero, err
	}
	id := ""
	for _, raw := range array(r["appIds"]) {
		d := dict(raw)
		if str(d["identifier"]) == bundle {
			id = str(d["appIdId"])
			break
		}
	}
	if id == "" {
		r, err = s.call(ctx, "ios/addAppId.action", team, map[string]any{"identifier": bundle, "name": safeName(name)})
		if err != nil {
			return zero, err
		}
		id = str(dict(r["appId"])["appIdId"])
	}
	if id == "" {
		return zero, fmt.Errorf("Apple returned no app identifier")
	}
	if len(groups) > 0 {
		if _, err = s.call(ctx, "ios/updateAppId.action", team, map[string]any{"appIdId": id, "APG3427HIY": true}); err != nil {
			return zero, err
		}
		r, err = s.call(ctx, "ios/listApplicationGroups.action", team, nil)
		if err != nil {
			return zero, err
		}
		existing := map[string]string{}
		for _, g := range array(r["applicationGroupList"]) {
			d := dict(g)
			existing[str(d["identifier"])] = str(d["applicationGroup"])
		}
		var ids []string
		for _, group := range groups {
			adjusted := group + "." + team
			gid := existing[adjusted]
			if gid == "" {
				r, err = s.call(ctx, "ios/addApplicationGroup.action", team, map[string]any{"identifier": adjusted, "name": safeName("AltStore " + group)})
				if err != nil {
					return zero, err
				}
				gid = str(dict(r["applicationGroup"])["applicationGroup"])
			}
			if gid == "" {
				return zero, fmt.Errorf("Apple returned no app group identifier")
			}
			ids = append(ids, gid)
		}
		if _, err = s.call(ctx, "ios/assignApplicationGroupToAppId.action", team, map[string]any{"appIdId": id, "applicationGroups": ids}); err != nil {
			return zero, err
		}
	}
	r, err = s.call(ctx, "ios/downloadTeamProvisioningProfile.action", team, map[string]any{"appIdId": id})
	if err != nil {
		return zero, err
	}
	p, err := profile.Parse(data(dict(r["provisioningProfile"])["encodedProfile"]))
	if err != nil {
		return zero, err
	}
	if p.BundleID() != bundle || !p.ExpirationDate.After(time.Now()) || !has(p.ProvisionedDevices, udid) || !has(p.TeamIdentifier, team) {
		return zero, fmt.Errorf("Apple returned a profile that does not authorize this app, team, and device")
	}
	certOK := false
	for _, der := range p.DeveloperCertificates {
		certOK = certOK || bytes.Equal(der, certificate.DER)
	}
	if !certOK {
		return zero, fmt.Errorf("profile does not include this server's certificate; regenerate the profile in the developer portal")
	}
	return p, nil
}
func has(xs []string, x string) bool {
	for _, v := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == ' ' || r == '-' {
			return r
		}
		return ' '
	}, s)
}
