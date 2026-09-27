package web

import (
	"altserver.local/altserver/internal/device"
	"altserver.local/altserver/internal/state"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var assets embed.FS

type session struct {
	csrf    string
	expires time.Time
}
type attempt struct {
	count int
	start time.Time
}
type Server struct {
	Jobs         *Jobs
	PasswordHash []byte
	SecureCookie bool
	MaxIPA       int64
	WorkDir      string
	ListDevices  func(context.Context) ([]device.Device, error)
	Status       func(context.Context) map[string]any
	Authorize    func(string, bool) error
	mu           sync.Mutex
	sessions     map[string]session
	attempts     map[string]attempt
}

func (s *Server) Handler() http.Handler {
	s.sessions = map[string]session{}
	s.attempts = map[string]attempt{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /api/v1/login", s.login)
	mux.HandleFunc("POST /api/v1/logout", s.protected(s.logout))
	mux.HandleFunc("GET /api/v1/session", s.protected(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("altserver_session")
		s.mu.Lock()
		v := s.sessions[cookie.Value]
		s.mu.Unlock()
		respond(w, 200, map[string]string{"csrf": v.csrf})
	}))
	mux.HandleFunc("GET /api/v1/status", s.protected(func(w http.ResponseWriter, r *http.Request) { respond(w, 200, s.Status(r.Context())) }))
	mux.HandleFunc("GET /api/v1/devices", s.protected(func(w http.ResponseWriter, r *http.Request) {
		ds, err := s.ListDevices(r.Context())
		if err != nil {
			problem(w, 503, err.Error())
			return
		}
		respond(w, 200, ds)
	}))
	mux.HandleFunc("POST /api/v1/devices/authorize", s.protected(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			UDID    string `json:"udid"`
			Enabled bool   `json:"enabled"`
		}
		if decode(w, r, &v) != nil || v.UDID == "" {
			problem(w, 400, "A device ID is required")
			return
		}
		ds, err := s.ListDevices(r.Context())
		if err != nil {
			problem(w, 503, err.Error())
			return
		}
		found := false
		for _, d := range ds {
			found = found || d.UDID == v.UDID
		}
		if v.Enabled && !found {
			problem(w, 400, "Device must be paired and connected before enabling refresh")
			return
		}
		if err = s.Authorize(v.UDID, v.Enabled); err != nil {
			problem(w, 500, "Could not save device authorization")
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/v1/jobs", s.protected(s.createJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.protected(s.getJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.protected(s.events))
	mux.HandleFunc("POST /api/v1/jobs/{id}/{action}", s.protected(s.jobAction))
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		if r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					problem(w, 403, "Cross-origin request rejected")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fmt.Errorf("JSON required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	s.mu.Lock()
	now := time.Now()
	for k, a := range s.attempts {
		if now.Sub(a.start) > 10*time.Minute {
			delete(s.attempts, k)
		}
	}
	a := s.attempts[host]
	if a.start.IsZero() {
		a.start = now
	}
	if a.count >= 5 || len(s.attempts) > 1024 {
		s.mu.Unlock()
		problem(w, 429, "Too many login attempts; wait ten minutes")
		return
	}
	a.count++
	s.attempts[host] = a
	s.mu.Unlock()
	var input struct {
		Password string `json:"password"`
	}
	if decode(w, r, &input) != nil {
		problem(w, 400, "Expected a JSON password")
		return
	}
	if bcrypt.CompareHashAndPassword(s.PasswordHash, []byte(input.Password)) != nil {
		problem(w, 401, "Invalid password")
		return
	}
	token, csrf := state.Token(), state.Token()
	s.mu.Lock()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= 32 {
		s.mu.Unlock()
		problem(w, 429, "Too many active sessions")
		return
	}
	s.sessions[token] = session{csrf: csrf, expires: now.Add(8 * time.Hour)}
	delete(s.attempts, host)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "altserver_session", Value: token, Path: "/", HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	respond(w, 200, map[string]string{"csrf": csrf})
}
func (s *Server) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("altserver_session")
		if err != nil {
			problem(w, 401, "Sign in required")
			return
		}
		s.mu.Lock()
		v, ok := s.sessions[cookie.Value]
		s.mu.Unlock()
		if !ok || time.Now().After(v.expires) {
			problem(w, 401, "Session expired")
			return
		}
		if r.Method != "GET" && r.Header.Get("X-CSRF-Token") != v.csrf {
			problem(w, 403, "Invalid CSRF token")
			return
		}
		next(w, r)
	}
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("altserver_session")
	s.mu.Lock()
	delete(s.sessions, cookie.Value)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "altserver_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]bool{"ok": true})
}
func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	if !s.Jobs.Reserve() {
		problem(w, 409, "An installation or upload is already in progress")
		return
	}
	started := false
	defer func() {
		if !started {
			s.Jobs.Release()
		}
	}()
	dir, err := os.MkdirTemp(s.WorkDir, "install-")
	if err != nil {
		problem(w, 500, "Cannot create upload directory")
		return
	}
	defer func() {
		if !started {
			os.RemoveAll(dir)
		}
	}()
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Minute))
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxIPA+(64<<10))
	reader, err := r.MultipartReader()
	if err != nil {
		problem(w, 400, "Multipart upload required")
		return
	}
	fields := map[string]string{}
	file := filepath.Join(dir, "input.ipa")
	hasFile := false
	for {
		part, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			problem(w, 400, "Upload is incomplete or exceeds the configured limit")
			return
		}
		name := part.FormName()
		if name == "ipa" {
			if hasFile {
				part.Close()
				problem(w, 400, "Only one IPA is allowed")
				return
			}
			hasFile = true
			f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				part.Close()
				problem(w, 500, "Cannot stage IPA")
				return
			}
			n, e := io.Copy(f, io.LimitReader(part, s.MaxIPA+1))
			ce := f.Close()
			part.Close()
			if e != nil || ce != nil || n == 0 || n > s.MaxIPA {
				problem(w, 413, "IPA is empty, too large, or could not be stored")
				return
			}
		} else {
			if name != "appleID" && name != "password" && name != "udid" {
				part.Close()
				problem(w, 400, "Unknown upload field")
				return
			}
			if _, exists := fields[name]; exists {
				part.Close()
				problem(w, 400, "Duplicate upload field")
				return
			}
			b, e := io.ReadAll(io.LimitReader(part, 1025))
			part.Close()
			if e != nil || len(b) > 1024 {
				problem(w, 400, "Invalid form field")
				return
			}
			fields[name] = string(b)
		}
	}
	if !hasFile || fields["appleID"] == "" || fields["password"] == "" || fields["udid"] == "" {
		problem(w, 400, "IPA, Apple ID, password, and device are required")
		return
	}
	ds, err := s.ListDevices(r.Context())
	found := false
	for _, d := range ds {
		found = found || d.UDID == fields["udid"]
	}
	if err != nil || !found {
		problem(w, 400, "Selected device is no longer connected")
		return
	}
	if r.Context().Err() != nil {
		return
	}
	j := s.Jobs.Start(Input{IPA: file, Directory: dir, AppleID: fields["appleID"], Password: fields["password"], UDID: fields["udid"]})
	started = true
	respond(w, 202, j.Snapshot())
}
func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	j := s.Jobs.Get(r.PathValue("id"))
	if j == nil {
		problem(w, 404, "Job not found")
		return
	}
	respond(w, 200, j.Snapshot())
}
func (s *Server) jobAction(w http.ResponseWriter, r *http.Request) {
	j := s.Jobs.Get(r.PathValue("id"))
	if j == nil {
		problem(w, 404, "Job not found")
		return
	}
	action := r.PathValue("action")
	if action == "cancel" {
		j.cancel()
		respond(w, 202, map[string]bool{"ok": true})
		return
	}
	var v struct {
		Value string `json:"value"`
	}
	if decode(w, r, &v) != nil {
		problem(w, 400, "Expected a JSON value")
		return
	}
	if err := j.Submit(action, v.Value); err != nil {
		problem(w, 409, err.Error())
		return
	}
	respond(w, 202, map[string]bool{"ok": true})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	j := s.Jobs.Get(r.PathValue("id"))
	if j == nil {
		problem(w, 404, "Job not found")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previous time.Time
	for {
		snap := j.Snapshot()
		if snap.Updated != previous {
			_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
			b, _ := json.Marshal(snap)
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			if controller.Flush() != nil {
				return
			}
			previous = snap.Updated
		}
		if snap.State == "complete" || snap.State == "failed" || snap.State == "cancelled" {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
