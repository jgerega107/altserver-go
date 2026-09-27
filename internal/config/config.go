package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	StateDir, WorkDir, WebAddr, ServerAddr, AnisetteURL, PasswordFile, Zsign, Interface string
	MaxIPA                                                                              int64
	MaxExpanded                                                                         int64
	OperationTimeout                                                                    time.Duration
	SecureCookie                                                                        bool
	Discovery                                                                           bool
}

func Load() (Config, error) {
	c := Config{StateDir: env("ALTSERVER_STATE_DIR", "/var/lib/altserver"), WorkDir: env("ALTSERVER_WORK_DIR", "/tmp/altserver"), WebAddr: env("ALTSERVER_WEB_ADDR", ":8080"), ServerAddr: env("ALTSERVER_LISTEN_ADDR", ":6968"), AnisetteURL: env("ALTSERVER_ANISETTE_URL", "http://127.0.0.1:6969"), PasswordFile: os.Getenv("ALTSERVER_ADMIN_PASSWORD_FILE"), Zsign: env("ALTSERVER_ZSIGN", "zsign"), Interface: os.Getenv("ALTSERVER_INTERFACE"), MaxIPA: 1 << 30, MaxExpanded: 4 << 30, OperationTimeout: 15 * time.Minute, Discovery: true}
	var err error
	if c.MaxIPA, err = strconv.ParseInt(env("ALTSERVER_MAX_IPA_BYTES", "1073741824"), 10, 64); err != nil || c.MaxIPA < 1 || c.MaxIPA > 16<<30 {
		return c, fmt.Errorf("ALTSERVER_MAX_IPA_BYTES must be between 1 and 17179869184")
	}
	if c.OperationTimeout, err = time.ParseDuration(env("ALTSERVER_OPERATION_TIMEOUT", "15m")); err != nil || c.OperationTimeout < time.Second {
		return c, fmt.Errorf("invalid ALTSERVER_OPERATION_TIMEOUT")
	}
	if c.SecureCookie, err = strconv.ParseBool(env("ALTSERVER_SECURE_COOKIE", "false")); err != nil {
		return c, err
	}
	if c.Discovery, err = strconv.ParseBool(env("ALTSERVER_DISCOVERY", "true")); err != nil {
		return c, err
	}
	for _, addr := range []string{c.WebAddr, c.ServerAddr} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return c, fmt.Errorf("invalid listen address: %w", err)
		}
	}
	u, err := url.Parse(c.AnisetteURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return c, fmt.Errorf("invalid ALTSERVER_ANISETTE_URL")
	}
	return c, nil
}
func env(k, d string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return d
}
