package main

import (
	"altserver.local/altserver/internal/anisette"
	"altserver.local/altserver/internal/apple"
	"altserver.local/altserver/internal/config"
	"altserver.local/altserver/internal/device"
	"altserver.local/altserver/internal/protocol"
	"altserver.local/altserver/internal/signing"
	"altserver.local/altserver/internal/state"
	"altserver.local/altserver/internal/web"
	"context"
	"errors"
	"fmt"
	"github.com/grandcat/zeroconf"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "device-worker":
			if err := device.Worker(os.Stdin, os.Stdout); err != nil {
				os.Exit(1)
			}
			return
		case "healthcheck":
			if err := healthcheck(); err != nil {
				os.Exit(1)
			}
			return
		case "serve":
		default:
			fmt.Fprintln(os.Stderr, "usage: altserver [serve|version|healthcheck]")
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func healthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	host, port, _ := net.SplitHostPort(cfg.WebAddr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	r, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("unhealthy")
	}
	return nil
}
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := state.New(cfg.StateDir)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(cfg.StateDir, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("state directory is already in use")
	}
	var identity state.Identity
	err = store.Read("identity.json", &identity)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read server identity: %w", err)
	}
	if identity.ServerID == "" {
		identity.ServerID = state.UUID()
	}
	if !regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`).MatchString(identity.ServerID) {
		return fmt.Errorf("invalid stored server identity")
	}
	if cfg.PasswordFile != "" {
		b, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return fmt.Errorf("cannot read admin password file")
		}
		password := strings.TrimRight(string(b), "\r\n")
		clear(b)
		if len(password) < 16 || len(password) > 72 {
			return fmt.Errorf("admin password must be 16–72 bytes")
		}
		if bcrypt.CompareHashAndPassword(identity.AdminHash, []byte(password)) != nil {
			identity.AdminHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
		}
		password = ""
	}
	if len(identity.AdminHash) == 0 {
		return fmt.Errorf("set ALTSERVER_ADMIN_PASSWORD_FILE to a file containing a 16–72 byte admin password")
	}
	if err = store.Write("identity.json", identity); err != nil {
		return err
	}
	workDir := filepath.Join(cfg.WorkDir, identity.ServerID)
	if err = os.MkdirAll(workDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "install-") || strings.HasPrefix(e.Name(), "refresh-") {
			if err = os.RemoveAll(filepath.Join(workDir, e.Name())); err != nil {
				return fmt.Errorf("cannot clean expired work files: %w", err)
			}
		}
	}
	var identityMu sync.Mutex
	allowed := func(id string) bool {
		identityMu.Lock()
		defer identityMu.Unlock()
		for _, d := range identity.Devices {
			if d == id {
				return true
			}
		}
		return false
	}
	authorize := func(id string, enabled bool) error {
		identityMu.Lock()
		defer identityMu.Unlock()
		next := identity
		next.Devices = nil
		for _, d := range identity.Devices {
			if d != id {
				next.Devices = append(next.Devices, d)
			}
		}
		if enabled {
			next.Devices = append(next.Devices, id)
		}
		if err := store.Write("identity.json", next); err != nil {
			return err
		}
		identity = next
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	provider := anisette.New(cfg.AnisetteURL)
	devices := &device.Manager{Backend: device.Process{}}
	appleClient := apple.New(provider)
	signer := &signing.Signer{Binary: cfg.Zsign, ServerID: identity.ServerID, MaxExpanded: cfg.MaxExpanded, Store: store}
	jobs := web.NewJobs(ctx, cfg.OperationTimeout, func(ctx context.Context, in web.Input, j *web.Job) error {
		session, err := appleClient.Login(ctx, in.AppleID, in.Password, j.Code)
		in.Password = ""
		if err != nil {
			return err
		}
		defer session.Close()
		teams, err := session.Teams(ctx)
		if err != nil {
			return err
		}
		team, err := j.Team(ctx, teams)
		if err != nil {
			return err
		}
		prepared, err := signer.Prepare(ctx, in.IPA, in.Directory, in.UDID, session, team, func(message string) { j.Update("running", message, 0) })
		if err != nil {
			return err
		}
		j.Update("running", "Installing on device", 0)
		if err = devices.Install(ctx, in.UDID, prepared.Path, prepared.Profiles, prepared.Active, func(p float64) { j.Update("running", "Installing on device", p) }); err != nil {
			return err
		}
		return authorize(in.UDID, true)
	})
	status := func(ctx context.Context) map[string]any {
		identityMu.Lock()
		id := identity.ServerID
		ds := append([]string(nil), identity.Devices...)
		identityMu.Unlock()
		a := "available"
		probe, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		if _, err := provider.Fetch(probe); err != nil {
			a = err.Error()
		}
		z := "available"
		if _, err := exec.LookPath(cfg.Zsign); err != nil {
			z = "not installed"
		}
		return map[string]any{"serverID": id, "authorizedDevices": ds, "anisette": a, "signing": z, "version": version, "deviceCompatibility": "unverified"}
	}
	webApp := &web.Server{Jobs: jobs, PasswordHash: identity.AdminHash, SecureCookie: cfg.SecureCookie, MaxIPA: cfg.MaxIPA, WorkDir: workDir, ListDevices: devices.List, Status: status, Authorize: authorize}
	httpServer := &http.Server{Addr: cfg.WebAddr, Handler: webApp.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := net.Listen("tcp", cfg.ServerAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	webListener, err := net.Listen("tcp", cfg.WebAddr)
	if err != nil {
		return err
	}
	defer webListener.Close()
	var discovery *zeroconf.Server
	if cfg.Discovery {
		var interfaces []net.Interface
		if cfg.Interface != "" {
			intf, e := net.InterfaceByName(cfg.Interface)
			if e != nil {
				return e
			}
			interfaces = []net.Interface{*intf}
		}
		discovery, err = zeroconf.Register("AltServer Linux "+identity.ServerID[:8], "_altserver._tcp", "local.", listener.Addr().(*net.TCPAddr).Port, []string{"serverID=" + identity.ServerID}, interfaces)
		if err != nil {
			return fmt.Errorf("Bonjour advertisement failed: %w", err)
		}
		defer discovery.Shutdown()
	}
	proto := &protocol.Server{Devices: devices, Anisette: provider, WorkDir: workDir, MaxIPA: cfg.MaxIPA, MaxExpanded: cfg.MaxExpanded, Timeout: cfg.OperationTimeout, Allowed: allowed}
	errs := make(chan error, 2)
	var serveWG sync.WaitGroup
	serveWG.Add(2)
	go func() { defer serveWG.Done(); errs <- httpServer.Serve(webListener) }()
	go func() { defer serveWG.Done(); errs <- proto.Serve(ctx, listener) }()
	slog.Info("AltServer started", "version", version, "web", cfg.WebAddr, "protocol", cfg.ServerAddr, "discovery", cfg.Discovery)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
		cancel()
	}
	cancel()
	shutdown, done := context.WithTimeout(context.Background(), 60*time.Second)
	defer done()
	if err = httpServer.Shutdown(shutdown); err != nil {
		httpServer.Close()
	}
	jobs.Wait()
	serveWG.Wait()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
