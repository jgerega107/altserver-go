package device

import (
	"altserver.local/altserver/internal/profile"
	"altserver.local/altserver/internal/testutil"
	"context"
	"errors"
	"testing"
)

type fakeBackend struct {
	profiles    [][]byte
	calls       []Request
	failInstall bool
}

func (b *fakeBackend) Run(ctx context.Context, r Request, _ func(float64)) (Event, error) {
	b.calls = append(b.calls, r)
	if r.Action == "profiles" {
		return Event{Profiles: b.profiles}, nil
	}
	if r.Action == "install" && b.failInstall {
		return Event{}, context.Canceled
	}
	return Event{}, nil
}
func TestInstallRestoresProfilesOnFailure(t *testing.T) {
	free := testutil.Profile(t, "free", "old", true)
	paid := testutil.Profile(t, "paid", "paid", false)
	incoming := testutil.Profile(t, "new", "new", true)
	backend := &fakeBackend{profiles: [][]byte{free.Data, paid.Data}, failInstall: true}
	m := Manager{Backend: backend}
	active := []string{"new"}
	err := m.Install(context.Background(), "device", "ipa", []profile.Profile{incoming}, &active, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var removed, restored int
	for _, r := range backend.calls {
		if r.Action == "remove-profile" {
			if r.UUID != "free" {
				t.Fatal("paid profile removed")
			}
			removed++
		}
		if r.Action == "install-profile" {
			p, _ := profile.Parse(r.Profile)
			if p.UUID != "free" {
				t.Fatal("wrong profile restored")
			}
			restored++
		}
	}
	if removed != 1 || restored != 1 {
		t.Fatalf("removed=%d restored=%d", removed, restored)
	}
}
func TestNilAndEmptyActiveProfilesDiffer(t *testing.T) {
	old := testutil.Profile(t, "old", "old.bundle", true)
	incoming := testutil.Profile(t, "new", "new.bundle", true)
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "empty"}[empty], func(t *testing.T) {
			backend := &fakeBackend{profiles: [][]byte{old.Data}}
			m := Manager{Backend: backend}
			var active *[]string
			if empty {
				active = &[]string{}
			}
			if err := m.Install(context.Background(), "device", "ipa", []profile.Profile{incoming}, active, nil); err != nil {
				t.Fatal(err)
			}
			restored := false
			removedIncoming := false
			for _, r := range backend.calls {
				restored = restored || r.Action == "install-profile"
				removedIncoming = removedIncoming || r.Action == "remove-profile" && r.UUID == "new"
			}
			if restored == empty || removedIncoming != empty {
				t.Fatalf("wrong active profile semantics: %+v", backend.calls)
			}
		})
	}
}
func TestDeviceLockCanBeCancelled(t *testing.T) {
	m := Manager{}
	unlock, err := m.lock(context.Background(), "one")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = m.lock(ctx, "one"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	other, err := m.lock(context.Background(), "two")
	if err != nil {
		t.Fatal(err)
	}
	other()
}
