package ipa

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsafeArchives(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "Payload/../../escape", "C:/escape", "Payload\\escape"} {
		t.Run(name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "bad.ipa")
			f, _ := os.Create(file)
			z := zip.NewWriter(f)
			w, _ := z.Create(name)
			w.Write([]byte("test"))
			z.Close()
			f.Close()
			if r, err := Open(file, 1000); err == nil {
				r.Close()
				t.Fatal("unsafe path accepted")
			}
		})
	}
}
func TestSymlinkAndDuplicateRejected(t *testing.T) {
	for _, link := range []bool{false, true} {
		file := filepath.Join(t.TempDir(), "bad.ipa")
		f, _ := os.Create(file)
		z := zip.NewWriter(f)
		h := &zip.FileHeader{Name: "Payload/Test.app/file"}
		if link {
			h.SetMode(os.ModeSymlink | 0777)
		}
		w, _ := z.CreateHeader(h)
		w.Write([]byte("x"))
		if !link {
			w, _ = z.Create("payload/test.app/file")
			w.Write([]byte("x"))
		}
		z.Close()
		f.Close()
		if r, err := Open(file, 1000); err == nil {
			r.Close()
			t.Fatal("unsafe entry accepted")
		}
	}
}
func TestExpansionLimit(t *testing.T) {
	file := filepath.Join(t.TempDir(), "big.ipa")
	f, _ := os.Create(file)
	z := zip.NewWriter(f)
	w, _ := z.Create("Payload/file")
	w.Write(make([]byte, 1024))
	z.Close()
	f.Close()
	if r, err := Open(file, 100); err == nil {
		r.Close()
		t.Fatal("expansion limit ignored")
	}
}
