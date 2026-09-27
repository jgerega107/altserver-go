// Package device isolates go-ios calls in bounded subprocesses. Closing a client
// connection does not reliably interrupt all third-party lockdown handshakes.
package device

import (
	"altserver.local/altserver/internal/profile"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

type Device struct {
	UDID       string `json:"udid"`
	Name       string `json:"name"`
	Connection string `json:"connection"`
}
type Request struct {
	Action   string
	UDID     string
	Path     string
	BundleID string
	Profile  []byte
	UUID     string
}
type Event struct {
	Progress *float64 `json:"progress,omitempty"`
	Devices  []Device `json:"devices,omitempty"`
	Profiles [][]byte `json:"profiles,omitempty"`
	Error    string   `json:"error,omitempty"`
	Done     bool     `json:"done,omitempty"`
}
type Backend interface {
	Run(context.Context, Request, func(float64)) (Event, error)
}
type Process struct{ Executable string }

func (p Process) Run(ctx context.Context, r Request, progress func(float64)) (Event, error) {
	exe := p.Executable
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return Event{}, err
		}
	}
	cmd := exec.CommandContext(ctx, exe, "device-worker")
	cmd.WaitDelay = 2 * time.Second
	in, err := cmd.StdinPipe()
	if err != nil {
		return Event{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return Event{}, err
	}
	// Never forward third-party logs; they may include pairing material.
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return Event{}, err
	}
	go func() { defer in.Close(); _ = json.NewEncoder(in).Encode(r) }()
	dec := json.NewDecoder(io.LimitReader(out, 32<<20))
	var final Event
	var readErr error
	for {
		var e Event
		if err = dec.Decode(&e); err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
		if e.Progress != nil && progress != nil {
			progress(*e.Progress)
		}
		if e.Done {
			final = e
		}
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return final, ctx.Err()
	}
	if err != nil || readErr != nil || !final.Done {
		return final, fmt.Errorf("device worker failed; check pairing, device trust, and usbmuxd socket access")
	}
	if final.Error != "" {
		return final, errors.New(final.Error)
	}
	return final, nil
}

type Manager struct {
	Backend Backend
	mu      sync.Mutex
	locks   map[string]chan struct{}
}

func (m *Manager) lock(ctx context.Context, udid string) (func(), error) {
	m.mu.Lock()
	if m.locks == nil {
		m.locks = map[string]chan struct{}{}
	}
	c := m.locks[udid]
	if c == nil {
		c = make(chan struct{}, 1)
		m.locks[udid] = c
	}
	m.mu.Unlock()
	select {
	case c <- struct{}{}:
		return func() { <-c }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (m *Manager) List(ctx context.Context) ([]Device, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	e, err := m.Backend.Run(ctx, Request{Action: "list"}, nil)
	return e.Devices, err
}
func (m *Manager) profiles(ctx context.Context, udid string) ([]profile.Profile, error) {
	e, err := m.Backend.Run(ctx, Request{Action: "profiles", UDID: udid}, nil)
	if err != nil {
		return nil, err
	}
	var profiles []profile.Profile
	for _, b := range e.Profiles {
		p, err := profile.Parse(b)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func (m *Manager) Install(ctx context.Context, udid, path string, incoming []profile.Profile, active *[]string, progress func(float64)) (result error) {
	unlock, err := m.lock(ctx, udid)
	if err != nil {
		return err
	}
	defer unlock()
	manage := active != nil
	for _, p := range incoming {
		manage = manage || p.LocalProvision
	}
	var removed []profile.Profile
	succeeded := false
	// Restore profiles even when the upload/installation context was cancelled.
	defer func() {
		if len(removed) == 0 && !manage {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if succeeded && active != nil {
			for _, p := range incoming {
				if !contains(*active, p.BundleID()) {
					_, e := m.Backend.Run(cleanup, Request{Action: "remove-profile", UDID: udid, UUID: p.UUID}, nil)
					result = errors.Join(result, e)
				}
			}
		}
		for _, p := range removed {
			if succeeded {
				if active != nil && !contains(*active, p.BundleID()) {
					continue
				}
				replaced := false
				for _, n := range incoming {
					if n.BundleID() == p.BundleID() {
						replaced = true
					}
				}
				if replaced {
					continue
				}
			}
			_, e := m.Backend.Run(cleanup, Request{Action: "install-profile", UDID: udid, Profile: p.Data}, nil)
			result = errors.Join(result, e)
		}
	}()
	if manage {
		profiles, e := m.profiles(ctx, udid)
		if e != nil {
			return e
		}
		for _, p := range profiles {
			if p.LocalProvision {
				if _, e = m.Backend.Run(ctx, Request{Action: "remove-profile", UDID: udid, UUID: p.UUID}, nil); e != nil {
					return e
				}
				removed = append(removed, p)
			}
		}
	}
	_, err = m.Backend.Run(ctx, Request{Action: "install", UDID: udid, Path: path}, progress)
	if err != nil {
		return err
	}
	succeeded = true
	return nil
}
func (m *Manager) InstallProfiles(ctx context.Context, udid string, raw [][]byte, active *[]string) (result error) {
	incoming := make([]profile.Profile, 0, len(raw))
	for _, b := range raw {
		p, e := profile.Parse(b)
		if e != nil {
			return e
		}
		incoming = append(incoming, p)
	}
	unlock, err := m.lock(ctx, udid)
	if err != nil {
		return err
	}
	defer unlock()
	old, err := m.profiles(ctx, udid)
	if err != nil {
		return err
	}
	var removed []profile.Profile
	var installed []profile.Profile
	defer func() {
		if result == nil {
			return
		}
		restore, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for _, p := range installed {
			_, e := m.Backend.Run(restore, Request{Action: "remove-profile", UDID: udid, UUID: p.UUID}, nil)
			result = errors.Join(result, e)
		}
		for _, p := range removed {
			_, e := m.Backend.Run(restore, Request{Action: "install-profile", UDID: udid, Profile: p.Data}, nil)
			result = errors.Join(result, e)
		}
	}()
	for _, p := range old {
		replace := false
		for _, n := range incoming {
			replace = replace || p.BundleID() == n.BundleID()
		}
		remove := replace
		if active != nil {
			remove = p.LocalProvision && (replace || !contains(*active, p.BundleID()))
		}
		if remove {
			if _, err = m.Backend.Run(ctx, Request{Action: "remove-profile", UDID: udid, UUID: p.UUID}, nil); err != nil {
				return err
			}
			removed = append(removed, p)
		}
	}
	for _, p := range incoming {
		if _, err = m.Backend.Run(ctx, Request{Action: "install-profile", UDID: udid, Profile: p.Data}, nil); err != nil {
			return err
		}
		installed = append(installed, p)
	}
	return nil
}
func (m *Manager) RemoveProfiles(ctx context.Context, udid string, bundles []string) error {
	unlock, err := m.lock(ctx, udid)
	if err != nil {
		return err
	}
	defer unlock()
	ps, err := m.profiles(ctx, udid)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if contains(bundles, p.BundleID()) {
			if _, err = m.Backend.Run(ctx, Request{Action: "remove-profile", UDID: udid, UUID: p.UUID}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func (m *Manager) RemoveApp(ctx context.Context, udid, bundle string) error {
	unlock, err := m.lock(ctx, udid)
	if err != nil {
		return err
	}
	defer unlock()
	_, err = m.Backend.Run(ctx, Request{Action: "uninstall", UDID: udid, BundleID: bundle}, nil)
	return err
}
