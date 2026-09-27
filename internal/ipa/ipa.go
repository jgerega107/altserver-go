package ipa

import (
	"altserver.local/altserver/internal/profile"
	"archive/zip"
	"context"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"howett.net/plist"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxMetadata = 8 << 20

type Bundle struct {
	Path, ID, Name string
	Info           map[string]any
	Entitlements   map[string]any
}

func safePath(name string) bool {
	return name != "" && !strings.Contains(name, "\\") && !strings.Contains(name, ":") && !strings.HasPrefix(name, "/") && path.Clean(name) != ".." && !strings.HasPrefix(path.Clean(name), "../") && !strings.ContainsRune(name, 0)
}
func Open(file string, maxExpanded int64) (*zip.ReadCloser, error) {
	r, err := zip.OpenReader(file)
	if err != nil {
		return nil, fmt.Errorf("invalid IPA zip archive")
	}
	var total uint64
	seen := map[string]bool{}
	for _, f := range r.File {
		key := strings.ToLower(path.Clean(f.Name))
		if len(r.File) > 100000 || !safePath(f.Name) || f.Mode()&os.ModeSymlink != 0 || (!f.Mode().IsRegular() && !f.FileInfo().IsDir()) || seen[key] {
			r.Close()
			return nil, fmt.Errorf("unsafe or unsupported IPA entry")
		}
		seen[key] = true
		if f.UncompressedSize64 > uint64(maxExpanded)-total {
			r.Close()
			return nil, fmt.Errorf("expanded IPA exceeds limit")
		}
		total += f.UncompressedSize64
	}
	return r, nil
}
func read(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > maxMetadata {
		return nil, fmt.Errorf("IPA metadata too large")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxMetadata+1))
	if len(b) > maxMetadata {
		return nil, fmt.Errorf("IPA metadata too large")
	}
	return b, err
}
func Profiles(file string, maxExpanded int64) ([]profile.Profile, error) {
	r, err := Open(file, maxExpanded)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	profiles := []profile.Profile{}
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, "/embedded.mobileprovision") {
			b, err := read(f)
			if err != nil {
				return nil, err
			}
			p, err := profile.Parse(b)
			if err != nil {
				return nil, err
			}
			profiles = append(profiles, p)
		}
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("signed IPA contains no provisioning profile")
	}
	return profiles, nil
}
func Extract(ctx context.Context, file, dir string, maxExpanded int64) ([]Bundle, error) {
	r, err := Open(file, maxExpanded)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		target := filepath.Join(dir, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(target, 0700); err != nil {
				return nil, err
			}
			continue
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return nil, err
		}
		src, e := f.Open()
		if e != nil {
			return nil, e
		}
		dst, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600|(f.Mode().Perm()&0111))
		if e != nil {
			src.Close()
			return nil, e
		}
		_, e = io.Copy(dst, src)
		closeErr := dst.Close()
		src.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	roots, err := filepath.Glob(filepath.Join(dir, "Payload", "*.app"))
	if err != nil || len(roots) != 1 {
		return nil, fmt.Errorf("IPA must contain exactly one Payload app")
	}
	root := roots[0]
	paths := []string{root}
	exts, _ := filepath.Glob(filepath.Join(root, "PlugIns", "*.appex"))
	paths = append(paths, exts...)
	var bundles []Bundle
	for _, p := range paths {
		b, err := os.ReadFile(filepath.Join(p, "Info.plist"))
		if err != nil || len(b) > maxMetadata {
			return nil, fmt.Errorf("missing or invalid bundle Info.plist")
		}
		info := map[string]any{}
		if _, err = plist.Unmarshal(b, &info); err != nil {
			return nil, err
		}
		id, _ := info["CFBundleIdentifier"].(string)
		name, _ := info["CFBundleDisplayName"].(string)
		if name == "" {
			name, _ = info["CFBundleName"].(string)
		}
		if id == "" {
			return nil, fmt.Errorf("bundle identifier missing")
		}
		exe, _ := info["CFBundleExecutable"].(string)
		if exe == "" || filepath.Base(exe) != exe || !safePath(exe) {
			return nil, fmt.Errorf("invalid bundle executable")
		}
		ent, err := entitlements(filepath.Join(p, exe))
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, Bundle{Path: p, ID: id, Name: name, Info: info, Entitlements: ent})
	}
	return bundles, nil
}
func entitlements(file string) (map[string]any, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var reader io.ReaderAt = f
	m, err := macho.NewFile(reader)
	if err != nil {
		fat, e := macho.NewFatFile(f)
		if e != nil || len(fat.Arches) == 0 {
			return nil, fmt.Errorf("invalid Mach-O executable")
		}
		arch := fat.Arches[0]
		reader = io.NewSectionReader(f, int64(arch.Offset), int64(arch.Size))
		m = arch.File
	}
	for _, l := range m.Loads {
		raw := l.Raw()
		if len(raw) < 16 || m.ByteOrder.Uint32(raw[:4]) != 0x1d {
			continue
		}
		offset, size := m.ByteOrder.Uint32(raw[8:12]), m.ByteOrder.Uint32(raw[12:16])
		if size > maxMetadata || size < 12 {
			return nil, fmt.Errorf("invalid Mach-O signature size")
		}
		b := make([]byte, size)
		if _, err = reader.ReadAt(b, int64(offset)); err != nil {
			return nil, err
		}
		be := binary.BigEndian
		if be.Uint32(b[:4]) != 0xfade0cc0 {
			return nil, fmt.Errorf("invalid Mach-O signature")
		}
		count := be.Uint32(b[8:12])
		if uint64(count)*8+12 > uint64(len(b)) {
			return nil, fmt.Errorf("invalid signature index")
		}
		for i := uint32(0); i < count; i++ {
			o := be.Uint32(b[16+i*8 : 20+i*8])
			if uint64(o)+8 > uint64(len(b)) {
				return nil, fmt.Errorf("invalid signature blob")
			}
			if be.Uint32(b[o:o+4]) == 0xfade7171 {
				n := be.Uint32(b[o+4 : o+8])
				if n < 8 || uint64(o)+uint64(n) > uint64(len(b)) {
					return nil, fmt.Errorf("invalid entitlement blob")
				}
				ent := map[string]any{}
				if _, err = plist.Unmarshal(b[o+8:o+n], &ent); err != nil {
					return nil, err
				}
				return ent, nil
			}
		}
	}
	return map[string]any{}, nil
}
