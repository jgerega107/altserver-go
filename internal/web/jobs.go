package web

import (
	"altserver.local/altserver/internal/apple"
	"altserver.local/altserver/internal/state"
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

type Input struct{ IPA, Directory, AppleID, Password, UDID string }
type Snapshot struct {
	ID       string       `json:"id"`
	State    string       `json:"state"`
	Message  string       `json:"message"`
	Progress float64      `json:"progress"`
	Teams    []apple.Team `json:"teams,omitempty"`
	Updated  time.Time    `json:"updated"`
}
type Job struct {
	mu       sync.Mutex
	snapshot Snapshot
	code     chan string
	team     chan string
	cancel   context.CancelFunc
	done     chan struct{}
}

func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := j.snapshot
	s.Teams = append([]apple.Team(nil), s.Teams...)
	return s
}
func (j *Job) Update(status, message string, progress float64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.snapshot.State = status
	j.snapshot.Message = message
	j.snapshot.Progress = progress
	j.snapshot.Updated = time.Now().UTC()
}
func (j *Job) Code(ctx context.Context) (string, error) {
	j.Update("needs_2fa", "Enter the six-digit code shown on your trusted Apple device.", 0)
	select {
	case code := <-j.code:
		j.Update("running", "Verifying Apple sign-in", 0)
		return code, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func (j *Job) Team(ctx context.Context, teams []apple.Team) (apple.Team, error) {
	j.mu.Lock()
	j.snapshot.Teams = append([]apple.Team(nil), teams...)
	j.mu.Unlock()
	j.Update("needs_team", "Choose the developer team to use.", 0)
	select {
	case id := <-j.team:
		for _, t := range teams {
			if t.ID == id {
				j.Update("running", "Preparing installation", 0)
				return t, nil
			}
		}
		return apple.Team{}, fmt.Errorf("invalid developer team")
	case <-ctx.Done():
		return apple.Team{}, ctx.Err()
	}
}
func (j *Job) Submit(kind, value string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	switch kind {
	case "code":
		if j.snapshot.State != "needs_2fa" {
			return fmt.Errorf("job is not waiting for a code")
		}
		if len(value) != 6 {
			return fmt.Errorf("code must contain six digits")
		}
		for _, c := range value {
			if c < '0' || c > '9' {
				return fmt.Errorf("code must contain six digits")
			}
		}
		select {
		case j.code <- value:
			j.snapshot.State = "running"
		default:
			return fmt.Errorf("code already submitted")
		}
	case "team":
		if j.snapshot.State != "needs_team" {
			return fmt.Errorf("job is not waiting for a team")
		}
		valid := false
		for _, t := range j.snapshot.Teams {
			valid = valid || t.ID == value
		}
		if !valid {
			return fmt.Errorf("invalid team")
		}
		select {
		case j.team <- value:
			j.snapshot.State = "running"
		default:
			return fmt.Errorf("team already submitted")
		}
	default:
		return fmt.Errorf("invalid input")
	}
	return nil
}

type Runner func(context.Context, Input, *Job) error
type Jobs struct {
	mu      sync.Mutex
	entries map[string]*Job
	slots   chan struct{}
	Run     Runner
	Timeout time.Duration
	Context context.Context
	wg      sync.WaitGroup
}

func NewJobs(ctx context.Context, timeout time.Duration, run Runner) *Jobs {
	return &Jobs{entries: map[string]*Job{}, slots: make(chan struct{}, 1), Run: run, Timeout: timeout, Context: ctx}
}
func (m *Jobs) Reserve() bool {
	select {
	case m.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (m *Jobs) Release() { <-m.slots }
func (m *Jobs) Start(in Input) *Job {
	ctx, cancel := context.WithTimeout(m.Context, m.Timeout)
	j := &Job{snapshot: Snapshot{ID: state.Token(), State: "running", Message: "Connecting to Apple", Updated: time.Now().UTC()}, code: make(chan string, 1), team: make(chan string, 1), cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	for id, old := range m.entries {
		if time.Since(old.Snapshot().Updated) > time.Hour {
			delete(m.entries, id)
		}
	}
	if len(m.entries) >= 20 {
		var oldest string
		var at time.Time
		for id, old := range m.entries {
			s := old.Snapshot()
			if oldest == "" || s.Updated.Before(at) {
				oldest = id
				at = s.Updated
			}
		}
		delete(m.entries, oldest)
	}
	m.entries[j.snapshot.ID] = j
	m.mu.Unlock()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(j.done)
		defer m.Release()
		defer cancel()
		defer os.RemoveAll(in.Directory)
		err := m.Run(ctx, in, j)
		in.Password = ""
		in.AppleID = ""
		if err != nil {
			if ctx.Err() != nil {
				j.Update("cancelled", "Operation cancelled or timed out. Check the device before retrying.", 0)
			} else {
				j.Update("failed", err.Error(), 0)
			}
		} else {
			j.Update("complete", "AltStore installed. Open it on your device to finish setup.", 1)
		}
	}()
	return j
}
func (m *Jobs) Get(id string) *Job { m.mu.Lock(); defer m.mu.Unlock(); return m.entries[id] }
func (m *Jobs) Wait()              { m.wg.Wait() }
