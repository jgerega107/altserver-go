//go:build ignore

// Run during the image build to preserve runtime Go module license notices.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	out := os.Args[1]
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/altserver")
	pipe, err := cmd.StdoutPipe()
	must(err)
	must(cmd.Start())
	dec := json.NewDecoder(pipe)
	seen := map[string]bool{}
	for {
		var p struct {
			Module *struct {
				Path, Version, Dir string
				Main               bool
			}
		}
		err = dec.Decode(&p)
		if err == io.EOF {
			break
		}
		must(err)
		m := p.Module
		if m == nil || m.Main || seen[m.Path] {
			continue
		}
		seen[m.Path] = true
		dir := filepath.Join(out, strings.ReplaceAll(m.Path, "/", "_"))
		must(os.MkdirAll(dir, 0755))
		must(os.WriteFile(filepath.Join(dir, "VERSION"), []byte(m.Path+" "+m.Version+"\n"), 0644))
		files, err := os.ReadDir(m.Dir)
		must(err)
		count := 0
		for _, f := range files {
			n := strings.ToUpper(f.Name())
			if !f.IsDir() && (strings.HasPrefix(n, "LICENSE") || strings.HasPrefix(n, "COPYING") || strings.HasPrefix(n, "NOTICE")) {
				b, err := os.ReadFile(filepath.Join(m.Dir, f.Name()))
				must(err)
				must(os.WriteFile(filepath.Join(dir, f.Name()), b, 0644))
				count++
			}
		}
		if count == 0 {
			panic(fmt.Sprintf("no license found for %s", m.Path))
		}
	}
	must(cmd.Wait())
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
