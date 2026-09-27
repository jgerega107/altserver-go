package signing

import (
	"altserver.local/altserver/internal/apple"
	"altserver.local/altserver/internal/ipa"
	"altserver.local/altserver/internal/profile"
	"altserver.local/altserver/internal/state"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"howett.net/plist"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
	"time"
)

type Signer struct {
	Binary      string
	ServerID    string
	MaxExpanded int64
	Store       *state.Store
}
type Result struct {
	Path     string
	Profiles []profile.Profile
	Active   *[]string
}

func (s *Signer) Prepare(ctx context.Context, input, dir, udid string, session *apple.Session, team apple.Team, progress func(string)) (Result, error) {
	var result Result
	if _, err := exec.LookPath(s.Binary); err != nil {
		return result, fmt.Errorf("zsign is unavailable")
	}
	progress("Inspecting AltStore IPA")
	bundles, err := ipa.Extract(ctx, input, filepath.Join(dir, "unpacked"), s.MaxExpanded)
	if err != nil {
		return result, err
	}
	root := bundles[0]
	if root.ID != "com.rileytestut.AltStore" && root.ID != "io.altstore.AltStore" {
		return result, fmt.Errorf("initial setup requires an original AltStore Classic IPA, not an already-renamed app")
	}
	progress("Registering device with Apple")
	if err = session.RegisterDevice(ctx, team.ID, udid, "AltServer Linux device"); err != nil {
		return result, err
	}
	progress("Preparing signing certificate")
	cert, err := session.Certificate(ctx, team.ID, s.Store)
	if err != nil {
		return result, err
	}
	keyBlock, _ := pem.Decode(cert.KeyPEM)
	if keyBlock == nil {
		return result, fmt.Errorf("invalid stored signing key")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return result, err
	}
	certificate, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		return result, err
	}
	p12, err := pkcs12.Legacy.Encode(key, certificate, nil, cert.MachineID)
	if err != nil {
		return result, err
	}
	keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "certificate.pem")
	if err = os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		return result, err
	}
	defer os.Remove(keyPath)
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.DER}), 0600); err != nil {
		return result, err
	}
	args := []string{"-q", "-f", "-k", keyPath, "-c", certPath}
	var active []string
	for i, b := range bundles {
		if b.ID != root.ID && !strings.HasPrefix(b.ID, root.ID+".") {
			return result, fmt.Errorf("extension identifier is outside its parent app")
		}
		newID := "com." + team.ID + "." + b.ID
		groups := stringsValue(b.Entitlements["com.apple.security.application-groups"])
		progress("Preparing provisioning profile for " + b.Name)
		p, err := session.Provision(ctx, team.ID, newID, b.Name, groups, cert, udid)
		if err != nil {
			return result, err
		}
		result.Profiles = append(result.Profiles, p)
		active = append(active, p.BundleID())
		b.Info["CFBundleIdentifier"] = p.BundleID()
		b.Info["ALTBundleIdentifier"] = b.ID
		b.Info["ALTAppGroups"] = p.Entitlements["com.apple.security.application-groups"]
		if b.Info["ALTAppGroups"] == nil {
			delete(b.Info, "ALTAppGroups")
		}
		if i == 0 {
			b.Info["ALTDeviceID"] = udid
			b.Info["ALTServerID"] = s.ServerID
			b.Info["ALTCertificateID"] = cert.Serial
			if err = os.WriteFile(filepath.Join(b.Path, "ALTCertificate.p12"), p12, 0600); err != nil {
				return result, err
			}
			types, _ := b.Info["CFBundleURLTypes"].([]any)
			b.Info["CFBundleURLTypes"] = append(types, map[string]any{"CFBundleTypeRole": "Editor", "CFBundleURLName": b.ID, "CFBundleURLSchemes": []string{"altstore-" + b.ID}})
		}
		info, err := plist.Marshal(b.Info, plist.XMLFormat)
		if err != nil {
			return result, err
		}
		if err = os.WriteFile(filepath.Join(b.Path, "Info.plist"), info, 0600); err != nil {
			return result, err
		}
		ppath := filepath.Join(dir, fmt.Sprintf("profile-%d.mobileprovision", i))
		if err = os.WriteFile(ppath, p.Data, 0600); err != nil {
			return result, err
		}
		args = append(args, "-m", ppath)
	}
	clear(p12)
	result.Path = filepath.Join(dir, "signed.ipa")
	args = append(args, "-o", result.Path, root.Path)
	progress("Signing AltStore and extensions")
	cmd := exec.CommandContext(ctx, s.Binary, args...)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("zsign failed; check that the IPA and profiles are supported")
	}
	if team.Free {
		result.Active = &active
	}
	return result, nil
}
func stringsValue(v any) []string {
	if a, ok := v.([]string); ok {
		return a
	}
	var out []string
	if a, ok := v.([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
