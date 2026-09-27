package protocol

import (
	"altserver.local/altserver/internal/anisette"
	"altserver.local/altserver/internal/profile"
	"altserver.local/altserver/internal/testutil"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type byteReader struct{ io.Reader }

func (r byteReader) Read(b []byte) (int, error) { return r.Reader.Read(b[:1]) }

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) { return w.Buffer.Write(b[:1]) }
func TestFraming(t *testing.T) {
	var b shortWriter
	if err := Write(&b, map[string]any{"identifier": "AnisetteDataRequest", "version": 1}); err != nil {
		t.Fatal(err)
	}
	var req Request
	if err := Read(byteReader{bytes.NewReader(b.Bytes())}, &req); err != nil {
		t.Fatal(err)
	}
	if req.Identifier != "AnisetteDataRequest" {
		t.Fatal(req)
	}
	for _, n := range []uint32{0, 0xffffffff, MaxMessage + 1} {
		if Read(bytes.NewReader(binary.LittleEndian.AppendUint32(nil, n)), &req) == nil {
			t.Fatal("invalid length accepted")
		}
	}
}

type fakeAnisette struct{}

func (fakeAnisette) Fetch(context.Context) (anisette.Data, error) {
	return anisette.Data{"machineID": "fixture"}, nil
}

type fakeDevices struct {
	called bool
	active *[]string
	ipa    []byte
}

func (d *fakeDevices) Install(_ context.Context, _ string, path string, _ []profile.Profile, active *[]string, p func(float64)) error {
	d.called = true
	d.active = active
	d.ipa, _ = os.ReadFile(path)
	p(0.5)
	return nil
}
func (*fakeDevices) InstallProfiles(context.Context, string, [][]byte, *[]string) error { return nil }
func (*fakeDevices) RemoveProfiles(context.Context, string, []string) error             { return nil }
func (*fakeDevices) RemoveApp(context.Context, string, string) error                    { return nil }
func TestPrepareRawIPAThenBegin(t *testing.T) {
	p := testutil.Profile(t, "id", "bundle", true)
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	entry, _ := z.Create("Payload/App.app/embedded.mobileprovision")
	entry.Write(p.Data)
	z.Close()
	d := &fakeDevices{}
	s := Server{Devices: d, Anisette: fakeAnisette{}, WorkDir: t.TempDir(), MaxIPA: 1 << 20, MaxExpanded: 1 << 20, Timeout: time.Second}
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); s.Handle(context.Background(), server) }()
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	Write(client, map[string]any{"identifier": "PrepareAppRequest", "version": 1, "udid": "device", "contentSize": archive.Len()})
	client.Write(archive.Bytes())
	Write(client, map[string]any{"identifier": "BeginInstallationRequest", "version": 3, "activeProfiles": []string{}})
	var response map[string]any
	for {
		if err := Read(client, &response); err != nil {
			t.Fatal(err)
		}
		if response["progress"] == float64(1) {
			break
		}
	}
	<-done
	if !d.called || d.active == nil || len(*d.active) != 0 || !bytes.Equal(d.ipa, archive.Bytes()) {
		t.Fatal("wrong install sequencing")
	}
	files, _ := os.ReadDir(s.WorkDir)
	if len(files) != 0 {
		t.Fatal("temporary IPA leaked")
	}
}
func TestUnknownRequestAndUnenrolledDevice(t *testing.T) {
	for _, id := range []string{"EnableUnsignedCodeExecutionRequest", "PrepareAppRequest"} {
		s := Server{Timeout: time.Second, Allowed: func(string) bool { return false }}
		a, b := net.Pipe()
		go s.Handle(context.Background(), a)
		Write(b, map[string]any{"identifier": id, "version": 1, "udid": "device"})
		var r map[string]any
		if err := Read(b, &r); err != nil {
			t.Fatal(err)
		}
		b.Close()
		want := float64(11)
		if id == "PrepareAppRequest" {
			want = 3
		}
		if r["errorCode"] != want || r["identifier"] != "ErrorResponse" {
			t.Fatal(r)
		}
	}
}
func FuzzRead(f *testing.F) {
	var b bytes.Buffer
	Write(&b, Request{Identifier: "AnisetteDataRequest", Version: 1})
	f.Add(b.Bytes())
	f.Add([]byte{255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, b []byte) { var r json.RawMessage; _ = Read(bytes.NewReader(b), &r) })
}
