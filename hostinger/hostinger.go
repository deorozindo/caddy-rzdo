// Package hostinger is a Caddy DNS provider for the Hostinger DNS API (ACME DNS-01).
// It only writes and removes the TXT record set of the challenge name.
package hostinger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

const api = "https://developers.hostinger.com/api/dns/v1/zones/"

type Provider struct {
	APIToken string `json:"api_token,omitempty"`
}

func init() { caddy.RegisterModule(Provider{}) }

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "dns.providers.hostinger", New: func() caddy.Module { return new(Provider) }}
}

func (p *Provider) Provision(caddy.Context) error {
	p.APIToken = caddy.NewReplacer().ReplaceAll(p.APIToken, "")
	if p.APIToken == "" {
		return fmt.Errorf("hostinger: missing API token")
	}
	return nil
}

// UnmarshalCaddyfile: `dns hostinger <token>`, e.g. `dns hostinger {env.HOSTINGER_API_TOKEN}`.
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if !d.NextArg() {
		return d.ArgErr()
	}
	p.APIToken = d.Val()
	if d.NextArg() {
		return d.Errf("unexpected argument '%s'", d.Val())
	}
	return nil
}

type rec struct {
	Content string `json:"content"`
}
type rrset struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Records []rec  `json:"records"`
}

func (p *Provider) call(ctx context.Context, method, zone string, body any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, method, api+strings.TrimSuffix(zone, "."), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("hostinger: %s %s: %d %s", method, zone, res.StatusCode, msg)
	}
	return nil
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var sets []rrset
	for _, r := range recs {
		rr := r.RR()
		ttl := int(rr.TTL.Seconds())
		if ttl < 60 {
			ttl = 120
		}
		sets = append(sets, rrset{Name: rr.Name, Type: rr.Type, TTL: ttl, Records: []rec{{Content: rr.Data}}})
	}
	if err := p.call(ctx, http.MethodPut, zone, map[string]any{"overwrite": false, "zone": sets}); err != nil {
		return nil, err
	}
	return recs, nil
}

// DeleteRecords removes the whole record set of each name and type (challenge names hold only ACME tokens).
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var f []map[string]string
	for _, r := range recs {
		rr := r.RR()
		f = append(f, map[string]string{"name": rr.Name, "type": rr.Type})
	}
	if err := p.call(ctx, http.MethodDelete, zone, map[string]any{"filters": f}); err != nil {
		return nil, err
	}
	return recs, nil
}

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
