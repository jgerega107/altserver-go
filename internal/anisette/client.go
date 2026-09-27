package anisette

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type Data map[string]string
type Provider interface {
	Fetch(context.Context) (Data, error)
}
type Client struct {
	URL  string
	HTTP *http.Client
}

func New(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (c *Client) Fetch(ctx context.Context) (Data, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anisette provider unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("anisette provider returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(b) > 65536 {
		return nil, fmt.Errorf("anisette response too large or incomplete")
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("invalid anisette JSON")
	}
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil {
					return s
				}
				var n json.Number
				if json.Unmarshal(v, &n) == nil {
					return n.String()
				}
			}
		}
		return ""
	}
	d := Data{"machineID": get("machineID", "X-Apple-I-MD-M"), "oneTimePassword": get("oneTimePassword", "X-Apple-I-MD"), "localUserID": get("localUserID", "X-Apple-I-MD-LU"), "routingInfo": get("routingInfo", "X-Apple-I-MD-RINFO"), "deviceUniqueIdentifier": get("deviceUniqueIdentifier", "X-Mme-Device-Id"), "deviceSerialNumber": get("deviceSerialNumber", "X-Apple-I-SRL-NO"), "deviceDescription": get("deviceDescription", "X-MMe-Client-Info"), "date": get("date", "X-Apple-I-Client-Time"), "locale": get("locale", "X-Apple-Locale"), "timeZone": get("timeZone", "X-Apple-I-TimeZone")}
	if d["date"] == "" {
		d["date"] = time.Now().UTC().Format(time.RFC3339)
	}
	if d["locale"] == "" {
		d["locale"] = "en_US"
	}
	if d["timeZone"] == "" {
		d["timeZone"] = "UTC"
	}
	// Some v1 providers omit the serial number; upstream AltServer uses this fallback too.
	if d["deviceSerialNumber"] == "" {
		d["deviceSerialNumber"] = "C02LKHBBFD57"
	}
	for k, v := range d {
		if v == "" {
			return nil, fmt.Errorf("anisette response missing %s", k)
		}
	}
	if _, err := strconv.ParseUint(d["routingInfo"], 10, 64); err != nil {
		return nil, fmt.Errorf("invalid anisette routing information")
	}
	if _, err := time.Parse(time.RFC3339, d["date"]); err != nil {
		return nil, fmt.Errorf("invalid anisette date")
	}
	return d, nil
}
func (d Data) Headers() map[string]string {
	return map[string]string{"X-Apple-I-MD-M": d["machineID"], "X-Apple-I-MD": d["oneTimePassword"], "X-Apple-I-MD-LU": d["localUserID"], "X-Apple-I-MD-RINFO": d["routingInfo"], "X-Mme-Device-Id": d["deviceUniqueIdentifier"], "X-Apple-I-SRL-NO": d["deviceSerialNumber"], "X-MMe-Client-Info": d["deviceDescription"], "X-Apple-I-Client-Time": d["date"], "X-Apple-Locale": d["locale"], "X-Apple-I-TimeZone": d["timeZone"]}
}
