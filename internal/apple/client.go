// Package apple implements the AltSign developer-service and GrandSlam flows.
// These are private Apple APIs; hardware/account acceptance is tracked separately.
package apple

import (
	"altserver.local/altserver/internal/anisette"
	"altserver.local/altserver/internal/state"
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"howett.net/plist"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const appTokenID = "com.apple.gs.xcode.auth"

type Client struct {
	HTTP                             *http.Client
	Anisette                         anisette.Provider
	GSA, Developer, Verify, Validate string
}
type Session struct {
	dsid, token string
	client      *Client
}
type Team struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Free bool   `json:"free"`
}
type Challenge func(context.Context) (string, error)

func New(provider anisette.Provider) *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, Anisette: provider, GSA: "https://gsa.apple.com/grandslam/GsService2", Developer: "https://developerservices2.apple.com/services/QH65B2/", Verify: "https://gsa.apple.com/auth/verify/trusteddevice", Validate: "https://gsa.apple.com/grandslam/GsService2/validate"}
}
func dict(v any) map[string]any { d, _ := v.(map[string]any); return d }
func str(v any) string          { s, _ := v.(string); return s }
func data(v any) []byte         { b, _ := v.([]byte); return b }
func number(v any) int64 {
	switch n := v.(type) {
	case uint64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}
func (c *Client) request(ctx context.Context, method, url string, payload any, headers map[string]string) (map[string]any, error) {
	var body []byte
	var err error
	if payload != nil {
		body, err = plist.Marshal(payload, plist.XMLFormat)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/x-xml-plist")
	req.Header.Set("Accept", "text/x-xml-plist")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Apple service connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Apple service returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(b) > 4<<20 {
		return nil, fmt.Errorf("Apple service response incomplete or too large")
	}
	// The trusted-device trigger acknowledges delivery with an HTTP status;
	// unlike validation, its successful body is not necessarily a plist.
	if method == "GET" && (url == c.Verify || len(b) == 0) {
		return map[string]any{}, nil
	}
	var result map[string]any
	if _, err = plist.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("Apple returned a non-plist response; its private API may have changed")
	}
	return result, nil
}
func (c *Client) auth(ctx context.Context, params map[string]any, a anisette.Data) (map[string]any, error) {
	h := a.Headers()
	h["User-Agent"] = "akd/1.0 CFNetwork/3860.500.111.2.2 Darwin/25.0.0"
	r, err := c.request(ctx, "POST", c.GSA, map[string]any{"Header": map[string]any{"Version": "1.0.1"}, "Request": params}, h)
	if err != nil {
		return nil, err
	}
	r = dict(r["Response"])
	if r == nil || dict(r["Status"]) == nil {
		return nil, fmt.Errorf("Apple login response missing status")
	}
	if ec := number(dict(r["Status"])["ec"]); ec != 0 {
		return nil, fmt.Errorf("Apple authentication rejected (code %d)", ec)
	}
	return r, nil
}
func (c *Client) Login(ctx context.Context, user, password string, challenge Challenge) (*Session, error) {
	for attempt := 0; attempt < 2; attempt++ {
		a, err := c.Anisette.Fetch(ctx)
		if err != nil {
			return nil, err
		}
		cpd := map[string]any{"bootstrap": true, "icscrec": true, "loc": a["locale"], "pbe": false, "prkgen": true, "svct": "iCloud"}
		for k, v := range a.Headers() {
			if k != "X-MMe-Client-Info" {
				cpd[k] = v
			}
		}
		routing, _ := strconv.ParseUint(a["routingInfo"], 10, 64)
		cpd["X-Apple-I-MD-RINFO"] = routing
		s, err := newSRP()
		if err != nil {
			return nil, err
		}
		r, err := c.auth(ctx, map[string]any{"A2k": padded(s.A), "ps": []string{"s2k", "s2k_fo"}, "cpd": cpd, "u": user, "o": "init"}, a)
		if err != nil {
			return nil, err
		}
		protocol := str(r["sp"])
		if err = s.challenge(user, password, data(r["s"]), data(r["B"]), int(number(r["i"])), protocol); err != nil {
			return nil, err
		}
		challengeID := str(r["c"])
		if challengeID == "" {
			return nil, fmt.Errorf("Apple login challenge missing identifier")
		}
		r, err = c.auth(ctx, map[string]any{"c": challengeID, "M1": s.proof, "cpd": cpd, "u": user, "o": "complete"}, a)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(s.serverProof, data(r["M2"])) {
			return nil, fmt.Errorf("Apple SRP server proof rejected")
		}
		spd, sc := data(r["spd"]), data(r["sc"])
		transcript := []byte("s2k,s2k_fo||" + protocol + "|")
		for _, v := range [][]byte{spd, sc} {
			if v != nil {
				transcript = binary.LittleEndian.AppendUint32(transcript, uint32(len(v)))
				transcript = append(transcript, v...)
			}
			transcript = append(transcript, '|')
		}
		if !hmac.Equal(data(r["np"]), mac(mac(s.key, []byte("HMAC key:")), digest(transcript))) {
			return nil, fmt.Errorf("Apple protocol negotiation proof rejected")
		}
		plain, err := decryptCBC(s.key, spd)
		clear(s.key)
		if err != nil {
			return nil, err
		}
		var session map[string]any
		_, err = plist.Unmarshal(plain, &session)
		clear(plain)
		if err != nil {
			return nil, fmt.Errorf("invalid decrypted Apple login response")
		}
		dsid, idms := str(session["adsid"]), str(session["GsIdmsToken"])
		if dsid == "" || idms == "" {
			return nil, fmt.Errorf("Apple login response missing identity")
		}
		authType := str(dict(r["Status"])["au"])
		if authType != "" {
			if authType != "trustedDeviceSecondaryAuth" {
				return nil, fmt.Errorf("Apple requires unsupported authentication method %s; use an account with a trusted Apple device", authType)
			}
			if attempt > 0 || challenge == nil {
				return nil, fmt.Errorf("Apple still requires two-factor authentication")
			}
			h := a.Headers()
			h["X-Apple-Identity-Token"] = base64.StdEncoding.EncodeToString([]byte(dsid + ":" + idms))
			h["X-Apple-App-Info"] = appTokenID
			h["User-Agent"] = "Xcode"
			h["X-Xcode-Version"] = "16.0 (16A242d)"
			if _, err = c.request(ctx, "GET", c.Verify, nil, h); err != nil {
				return nil, err
			}
			code, err := challenge(ctx)
			if err != nil {
				return nil, err
			}
			if len(code) != 6 {
				return nil, fmt.Errorf("verification code must contain six digits")
			}
			for _, ch := range code {
				if ch < '0' || ch > '9' {
					return nil, fmt.Errorf("verification code must contain six digits")
				}
			}
			h["security-code"] = code
			v, err := c.request(ctx, "GET", c.Validate, nil, h)
			if err != nil {
				return nil, err
			}
			if ec := number(v["ec"]); ec != 0 {
				return nil, fmt.Errorf("Apple rejected verification code (%d)", ec)
			}
			continue
		}
		sk := data(session["sk"])
		if len(sk) == 0 || len(data(session["c"])) == 0 {
			return nil, fmt.Errorf("Apple login missing token keys")
		}
		r, err = c.auth(ctx, map[string]any{"u": dsid, "app": []string{appTokenID}, "c": session["c"], "t": idms, "checksum": mac(sk, []byte("apptokens"), []byte(dsid), []byte(appTokenID)), "cpd": cpd, "o": "apptokens"}, a)
		if err != nil {
			return nil, err
		}
		plain, err = decryptToken(sk, data(r["et"]))
		clear(sk)
		if err != nil {
			return nil, fmt.Errorf("Apple app token authentication failed")
		}
		var tokens map[string]any
		_, err = plist.Unmarshal(plain, &tokens)
		clear(plain)
		if err != nil {
			return nil, fmt.Errorf("invalid Apple token payload")
		}
		token := str(dict(dict(tokens["t"])[appTokenID])["token"])
		if token == "" {
			return nil, fmt.Errorf("Apple did not issue a developer token")
		}
		return &Session{dsid: dsid, token: token, client: c}, nil
	}
	return nil, fmt.Errorf("authentication did not complete")
}
func (s *Session) call(ctx context.Context, action, team string, extra map[string]any) (map[string]any, error) {
	a, err := s.client.Anisette.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	params := map[string]any{"clientId": "XABBG36SBA", "protocolVersion": "QH65B2", "requestId": state.UUID()}
	if team != "" {
		params["teamId"] = team
	}
	for k, v := range extra {
		params[k] = v
	}
	h := a.Headers()
	h["User-Agent"] = "Xcode"
	h["X-Xcode-Version"] = "16.0 (16A242d)"
	h["X-Apple-App-Info"] = appTokenID
	h["X-Apple-I-Identity-Id"] = s.dsid
	h["X-Apple-GS-Token"] = s.token
	h["X-Apple-I-Locale"] = a["locale"]
	r, err := s.client.request(ctx, "POST", s.client.Developer+action+"?clientId=XABBG36SBA", params, h)
	if err != nil {
		return nil, err
	}
	if _, ok := r["resultCode"]; !ok {
		return nil, fmt.Errorf("Apple developer response missing result code")
	}
	if ec := number(r["resultCode"]); ec != 0 {
		return nil, fmt.Errorf("Apple developer operation %s rejected (code %d)", action, ec)
	}
	return r, nil
}
func (s *Session) Teams(ctx context.Context) ([]Team, error) {
	r, err := s.call(ctx, "listTeams.action", "", nil)
	if err != nil {
		return nil, err
	}
	teams := []Team{}
	for _, raw := range array(r["teams"]) {
		d := dict(raw)
		id := str(d["teamId"])
		if id == "" {
			return nil, fmt.Errorf("invalid Apple team")
		}
		memberships := array(d["memberships"])
		free := str(d["type"]) == "Individual" && len(memberships) == 1 && strings.Contains(strings.ToLower(str(dict(memberships[0])["name"])), "free")
		teams = append(teams, Team{ID: id, Name: str(d["name"]), Free: free})
	}
	if len(teams) == 0 {
		return nil, fmt.Errorf("no developer teams available; accept Apple developer agreements first")
	}
	return teams, nil
}
func array(v any) []any   { a, _ := v.([]any); return a }
func (s *Session) Close() { s.dsid = ""; s.token = "" }
