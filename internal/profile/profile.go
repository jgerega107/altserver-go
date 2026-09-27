package profile

import (
	"fmt"
	"go.mozilla.org/pkcs7"
	"howett.net/plist"
	"strings"
	"time"
)

type Profile struct {
	UUID                  string
	Name                  string
	TeamIdentifier        []string
	Entitlements          map[string]any
	ProvisionedDevices    []string
	DeveloperCertificates [][]byte
	ExpirationDate        time.Time
	LocalProvision        bool
	Data                  []byte `plist:"-"`
}

func Parse(data []byte) (Profile, error) {
	var p Profile
	signed, err := pkcs7.Parse(data)
	if err != nil {
		return p, fmt.Errorf("invalid provisioning profile CMS: %w", err)
	}
	if _, err = plist.Unmarshal(signed.Content, &p); err != nil {
		return p, fmt.Errorf("invalid provisioning profile plist: %w", err)
	}
	if p.UUID == "" || p.BundleID() == "" || len(p.TeamIdentifier) == 0 {
		return p, fmt.Errorf("incomplete provisioning profile")
	}
	p.Data = data
	return p, nil
}
func (p Profile) BundleID() string {
	id, _ := p.Entitlements["application-identifier"].(string)
	_, id, ok := strings.Cut(id, ".")
	if !ok {
		return ""
	}
	return id
}
