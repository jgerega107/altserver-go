package web

import (
	"altserver.local/altserver/internal/device"
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin-test-password"), bcrypt.MinCost)
	ctx, cancel := context.WithCancel(context.Background())
	jobs := NewJobs(ctx, time.Second, func(ctx context.Context, in Input, j *Job) error { <-ctx.Done(); return ctx.Err() })
	t.Cleanup(func() { cancel(); jobs.Wait() })
	s := &Server{Jobs: jobs, PasswordHash: hash, MaxIPA: 16, WorkDir: t.TempDir(), ListDevices: func(context.Context) ([]device.Device, error) {
		return []device.Device{{UDID: "device", Name: "Fixture"}}, nil
	}, Status: func(context.Context) map[string]any { return map[string]any{"ok": true} }, Authorize: func(string, bool) error { return nil }}
	return s, s.Handler()
}
func loginTest(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequest("POST", "http://server/api/v1/login", strings.NewReader(`{"password":"admin-test-password"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var v map[string]string
	json.Unmarshal(w.Body.Bytes(), &v)
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure session cookie")
	}
	return cookie, v["csrf"]
}
func TestAuthenticationAndCSRF(t *testing.T) {
	_, h := fixtureServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://server/api/v1/devices", nil))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie, csrf := loginTest(t, h)
	for _, test := range []struct {
		origin, token string
		want          int
	}{{"http://evil.invalid", csrf, 403}, {"http://server", "", 403}, {"http://server", csrf, 200}} {
		r := httptest.NewRequest("POST", "http://server/api/v1/logout", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", test.origin)
		r.Header.Set("X-CSRF-Token", test.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("got %d want %d", w.Code, test.want)
		}
	}
}
func TestLoginRateLimit(t *testing.T) {
	_, h := fixtureServer(t)
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "http://server/api/v1/login", strings.NewReader(`{"password":"wrong"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
}
func TestUploadLimitAndCleanup(t *testing.T) {
	s, h := fixtureServer(t)
	cookie, csrf := loginTest(t, h)
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	part, _ := m.CreateFormFile("ipa", "arbitrary.ipa")
	part.Write(make([]byte, 17))
	m.Close()
	r := httptest.NewRequest("POST", "http://server/api/v1/jobs", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal(w.Body.String())
	}
	files, _ := os.ReadDir(s.WorkDir)
	if len(files) != 0 {
		t.Fatal("upload leaked")
	}
	if !s.Jobs.Reserve() {
		t.Fatal("upload slot leaked")
	}
	s.Jobs.Release()
}
func TestCancelledJobDoesNotExposeSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	work := filepath.Join(dir, "job")
	os.Mkdir(work, 0700)
	jman := NewJobs(ctx, time.Minute, func(ctx context.Context, in Input, j *Job) error { _, err := j.Code(ctx); return err })
	if !jman.Reserve() {
		t.Fatal("cannot reserve")
	}
	j := jman.Start(Input{Directory: work, AppleID: "private@example.invalid", Password: "private-password"})
	j.cancel()
	select {
	case <-j.done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not finish")
	}
	b, _ := json.Marshal(j.Snapshot())
	if bytes.Contains(b, []byte("private")) {
		t.Fatal("snapshot leaks credentials")
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("work directory remains")
	}
}
func TestUnknownJobAndHealth(t *testing.T) {
	_, h := fixtureServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://server/healthz", nil))
	b, _ := io.ReadAll(w.Result().Body)
	if w.Code != 200 || string(b) != "ok\n" {
		t.Fatal(w.Code)
	}
	cookie, _ := loginTest(t, h)
	r := httptest.NewRequest("GET", "http://server/api/v1/jobs/missing", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
