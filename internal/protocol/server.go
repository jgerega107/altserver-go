package protocol

import (
	"altserver.local/altserver/internal/anisette"
	"altserver.local/altserver/internal/ipa"
	"altserver.local/altserver/internal/profile"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const MaxMessage = 16 << 20

type Request struct {
	Version              int       `json:"version"`
	Identifier           string    `json:"identifier"`
	UDID                 string    `json:"udid"`
	ContentSize          int64     `json:"contentSize"`
	ActiveProfiles       *[]string `json:"activeProfiles"`
	ProvisioningProfiles [][]byte  `json:"provisioningProfiles"`
	BundleIdentifiers    []string  `json:"bundleIdentifiers"`
	BundleIdentifier     string    `json:"bundleIdentifier"`
}
type Devices interface {
	Install(context.Context, string, string, []profile.Profile, *[]string, func(float64)) error
	InstallProfiles(context.Context, string, [][]byte, *[]string) error
	RemoveProfiles(context.Context, string, []string) error
	RemoveApp(context.Context, string, string) error
}
type Server struct {
	Devices             Devices
	Anisette            anisette.Provider
	WorkDir             string
	MaxIPA, MaxExpanded int64
	Timeout             time.Duration
	Allowed             func(string) bool
	uploads             chan struct{}
}

func Read(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > MaxMessage {
		return fmt.Errorf("invalid message length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("response too large")
	}
	header := binary.LittleEndian.AppendUint32(nil, uint32(len(b)))
	if err = writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func reply(w io.Writer, id string, fields map[string]any) error {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["identifier"] = id
	fields["version"] = 1
	return Write(w, fields)
}
func fail(w io.Writer, code int) { _ = reply(w, "ErrorResponse", map[string]any{"errorCode": code}) }
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	s.uploads = make(chan struct{}, 4)
	slots := make(chan struct{}, 32)
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); s.Handle(ctx, c) }()
		default:
			c.Close()
		}
	}
}
func (s *Server) Handle(parent context.Context, c net.Conn) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(parent, s.Timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	var r Request
	if err := Read(c, &r); err != nil {
		fail(c, 5)
		return
	}
	if r.Version < 1 || r.Version > 3 {
		fail(c, 5)
		return
	}
	if r.Identifier == "AnisetteDataRequest" {
		a, err := s.Anisette.Fetch(ctx)
		if err != nil {
			fail(c, 13)
			return
		}
		_ = reply(c, "AnisetteDataResponse", map[string]any{"anisetteData": a})
		return
	}
	switch r.Identifier {
	case "PrepareAppRequest", "InstallProvisioningProfilesRequest", "RemoveProvisioningProfilesRequest", "RemoveAppRequest":
	default:
		fail(c, 11)
		return
	}
	if r.UDID == "" || len(r.UDID) > 128 {
		fail(c, 5)
		return
	}
	if s.Allowed != nil && !s.Allowed(r.UDID) {
		fail(c, 3)
		return
	}
	switch r.Identifier {
	case "PrepareAppRequest":
		if r.ContentSize < 1 || r.ContentSize > s.MaxIPA {
			fail(c, 5)
			return
		}
		if s.uploads != nil {
			select {
			case s.uploads <- struct{}{}:
				defer func() { <-s.uploads }()
			case <-ctx.Done():
				return
			}
		}
		f, err := os.CreateTemp(s.WorkDir, "refresh-*.ipa")
		if err != nil {
			fail(c, 4)
			return
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if _, err = io.CopyN(f, c, r.ContentSize); err != nil {
			fail(c, 2)
			return
		}
		if err = f.Close(); err != nil {
			fail(c, 4)
			return
		}
		var begin Request
		if err = Read(c, &begin); err != nil || begin.Identifier != "BeginInstallationRequest" || begin.Version < 1 || begin.Version > 3 {
			fail(c, 5)
			return
		}
		profiles, err := ipa.Profiles(f.Name(), s.MaxExpanded)
		if err != nil {
			fail(c, 7)
			return
		}
		var writeErr error
		last := time.Time{}
		err = s.Devices.Install(ctx, r.UDID, f.Name(), profiles, begin.ActiveProfiles, func(p float64) {
			if writeErr != nil || time.Since(last) < 200*time.Millisecond || p >= 1 {
				return
			}
			last = time.Now()
			writeErr = reply(c, "InstallationProgressResponse", map[string]any{"progress": p})
			if writeErr != nil {
				cancel()
			}
		})
		if err != nil {
			fail(c, 8)
			return
		}
		_ = reply(c, "InstallationProgressResponse", map[string]any{"progress": 1.0})
	case "InstallProvisioningProfilesRequest":
		if len(r.ProvisioningProfiles) == 0 {
			fail(c, 5)
			return
		}
		if err := s.Devices.InstallProfiles(ctx, r.UDID, r.ProvisioningProfiles, r.ActiveProfiles); err != nil {
			fail(c, 8)
			return
		}
		_ = reply(c, "InstallProvisioningProfilesResponse", nil)
	case "RemoveProvisioningProfilesRequest":
		if len(r.BundleIdentifiers) == 0 {
			fail(c, 5)
			return
		}
		if err := s.Devices.RemoveProfiles(ctx, r.UDID, r.BundleIdentifiers); err != nil {
			fail(c, 15)
			return
		}
		_ = reply(c, "RemoveProvisioningProfilesResponse", nil)
	case "RemoveAppRequest":
		if r.BundleIdentifier == "" {
			fail(c, 5)
			return
		}
		if err := s.Devices.RemoveApp(ctx, r.UDID, r.BundleIdentifier); err != nil {
			fail(c, 16)
			return
		}
		_ = reply(c, "RemoveAppResponse", nil)
	}
}
