package anisette

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderConversion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"X-Apple-I-MD-M": "machine", "X-Apple-I-MD": "otp", "X-Apple-I-MD-LU": "user", "X-Apple-I-MD-RINFO": 17106176, "X-Mme-Device-Id": "device", "X-MMe-Client-Info": "client"})
	}))
	defer srv.Close()
	d, err := New(srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d["machineID"] != "machine" || d["routingInfo"] != "17106176" || d["date"] == "" {
		t.Fatal(d)
	}
}
func TestNoRedirectOrIncompleteFallback(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer srv.Close()
	if _, err := New(srv.URL).Fetch(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	if hits != 0 {
		t.Fatal("redirect followed")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"X-Apple-I-MD":"secret"}`)) }))
	defer bad.Close()
	if _, err := New(bad.URL).Fetch(context.Background()); err == nil {
		t.Fatal("incomplete identity accepted")
	}
}
