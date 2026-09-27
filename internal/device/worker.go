package device

import (
	"altserver.local/altserver/internal/state"
	"encoding/json"
	"fmt"
	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/afc"
	"io"
	"os"
	"path"
)

func Worker(in io.Reader, out io.Writer) error {
	var r Request
	if err := json.NewDecoder(io.LimitReader(in, 24<<20)).Decode(&r); err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	e, err := work(r, func(p float64) { _ = enc.Encode(Event{Progress: &p}) })
	e.Done = true
	if err != nil {
		e.Error = err.Error()
	}
	return enc.Encode(e)
}
func work(r Request, progress func(float64)) (Event, error) {
	list, err := ios.ListDevices()
	if err != nil {
		return Event{}, fmt.Errorf("cannot contact usbmuxd; check socket permissions and host service")
	}
	if r.Action == "list" {
		ds := []Device{}
		seen := map[string]bool{}
		for _, d := range list.DeviceList {
			u := d.Properties.SerialNumber
			if seen[u] {
				continue
			}
			seen[u] = true
			ds = append(ds, Device{UDID: u, Name: u, Connection: d.Properties.ConnectionType})
		}
		return Event{Devices: ds}, nil
	}
	var d ios.DeviceEntry
	found := false
	for _, candidate := range list.DeviceList {
		if candidate.Properties.SerialNumber == r.UDID {
			d = candidate
			found = true
			if d.Properties.ConnectionType == "USB" {
				break
			}
		}
	}
	if !found {
		return Event{}, fmt.Errorf("device not found; connect USB or enable Wi-Fi pairing")
	}
	switch r.Action {
	case "profiles", "install-profile", "remove-profile":
		return misagent(d, r)
	case "install":
		return Event{}, install(d, r.Path, progress)
	case "uninstall":
		return Event{}, proxy(d, map[string]any{"Command": "Uninstall", "ApplicationIdentifier": r.BundleID, "ClientOptions": map[string]any{}}, nil)
	default:
		return Event{}, fmt.Errorf("unsupported device operation")
	}
}
func misagent(d ios.DeviceEntry, r Request) (Event, error) {
	c, err := ios.ConnectToService(d, "com.apple.misagent")
	if err != nil {
		return Event{}, fmt.Errorf("cannot open provisioning service; unlock and trust the device")
	}
	defer c.Close()
	codec := ios.NewPlistCodec()
	req := map[string]any{"ProfileType": "Provisioning"}
	switch r.Action {
	case "profiles":
		req["MessageType"] = "CopyAll"
	case "install-profile":
		req["MessageType"] = "Install"
		req["Payload"] = r.Profile
	case "remove-profile":
		req["MessageType"] = "Remove"
		req["ProfileID"] = r.UUID
	}
	b, err := codec.Encode(req)
	if err != nil {
		return Event{}, err
	}
	if err = c.Send(b); err != nil {
		return Event{}, fmt.Errorf("provisioning request failed")
	}
	b, err = codec.Decode(c.Reader())
	if err != nil {
		return Event{}, fmt.Errorf("provisioning response failed")
	}
	v, err := ios.ParsePlist(b)
	if err != nil {
		return Event{}, fmt.Errorf("invalid provisioning response")
	}
	status, ok := v["Status"]
	if !ok || fmt.Sprint(status) != "0" {
		return Event{}, fmt.Errorf("provisioning service returned status %v", status)
	}
	e := Event{}
	if r.Action == "profiles" {
		raw, ok := v["Payload"].([]any)
		if !ok {
			return e, fmt.Errorf("invalid profile list")
		}
		for _, p := range raw {
			b, ok := p.([]byte)
			if !ok {
				return e, fmt.Errorf("invalid profile payload")
			}
			e.Profiles = append(e.Profiles, b)
		}
	}
	return e, nil
}
func proxy(d ios.DeviceEntry, request map[string]any, progress func(float64)) error {
	c, err := ios.ConnectToService(d, "com.apple.mobile.installation_proxy")
	if err != nil {
		return fmt.Errorf("cannot open installation service; unlock and trust the device")
	}
	defer c.Close()
	codec := ios.NewPlistCodec()
	b, err := codec.Encode(request)
	if err != nil {
		return err
	}
	if err = c.Send(b); err != nil {
		return fmt.Errorf("installation request failed")
	}
	for {
		b, err = codec.Decode(c.Reader())
		if err != nil {
			return fmt.Errorf("installation connection lost")
		}
		v, err := ios.ParsePlist(b)
		if err != nil {
			return fmt.Errorf("invalid installation response")
		}
		if code, ok := v["Error"]; ok {
			return fmt.Errorf("device installation error: %v", code)
		}
		if p, ok := v["PercentComplete"].(uint64); ok && progress != nil {
			progress(0.5 + float64(p)/200)
		}
		if v["Status"] == "Complete" {
			return nil
		}
	}
}
func install(d ios.DeviceEntry, file string, progress func(float64)) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot read staged IPA")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	c, err := afc.New(d)
	if err != nil {
		return fmt.Errorf("cannot open device file service")
	}
	defer c.Close()
	if err = c.MkDir("PublicStaging"); err != nil {
		if _, e := c.Stat("PublicStaging"); e != nil {
			return fmt.Errorf("cannot create device staging directory")
		}
	}
	remote := path.Join("PublicStaging", state.UUID()+".ipa")
	dest, err := c.Open(remote, afc.Mode(3))
	if err != nil {
		return fmt.Errorf("cannot create device staging file")
	}
	defer c.Remove(remote)
	buf := make([]byte, 64<<10)
	var sent int64
	for {
		n, e := f.Read(buf)
		if n > 0 {
			if _, err = dest.Write(buf[:n]); err != nil {
				dest.Close()
				return fmt.Errorf("device upload failed")
			}
			sent += int64(n)
			if progress != nil && info.Size() > 0 {
				progress(0.5 * float64(sent) / float64(info.Size()))
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			dest.Close()
			return e
		}
	}
	if err = dest.Close(); err != nil {
		return fmt.Errorf("cannot finalize device upload")
	}
	return proxy(d, map[string]any{"Command": "Install", "PackagePath": remote, "ClientOptions": map[string]any{"PackageType": "Developer"}}, progress)
}
