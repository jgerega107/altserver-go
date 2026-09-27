// Package testutil generates synthetic profiles; no Apple credentials are used.
package testutil

import (
	"altserver.local/altserver/internal/profile"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	"math/big"
	"testing"
	"time"
)

func Profile(t testing.TB, id, bundle string, free bool) profile.Profile {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test only"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	content, err := plist.Marshal(map[string]any{"UUID": id, "Name": "Fixture", "TeamIdentifier": []string{"TEAM"}, "ExpirationDate": time.Now().Add(time.Hour), "Entitlements": map[string]any{"application-identifier": "TEAM." + bundle}, "LocalProvision": free, "ProvisionedDevices": []string{"device"}, "DeveloperCertificates": [][]byte{der}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err = signed.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	data, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
