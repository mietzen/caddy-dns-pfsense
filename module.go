package pfsense

import (
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.pfsense",
		New: func() caddy.Module { return &Provider{} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()

	p.Host = strings.TrimSpace(repl.ReplaceAll(p.Host, ""))
	p.APIKey = strings.TrimSpace(repl.ReplaceAll(p.APIKey, ""))
	p.EntryDescription = strings.TrimSpace(repl.ReplaceAll(p.EntryDescription, ""))
	p.Logger = ctx.Logger()

	p.Logger.Info("pfSense DNS provider initialized")
	p.Logger.Debug("pfSense DNS provider configuration",
		zap.String("host", p.Host),
		zap.Bool("insecure", p.Insecure),
		zap.String("entry_description", p.EntryDescription),
	)

	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	pfsense {
//	    host <host>
//	    api_key <api_key>
//	    insecure <true|false>
//	    entry_description <description>
//	}
//
// Required: host, api_key
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "host":
				if d.NextArg() {
					p.Host = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "api_key":
				if d.NextArg() {
					p.APIKey = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "insecure":
				if d.NextArg() {
					val := strings.ToLower(d.Val())
					p.Insecure = val == "true" || val == "1" || val == "yes" || val == "on"
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "entry_description":
				if d.NextArg() {
					p.EntryDescription = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Host == "" {
		return d.Err("missing host")
	}
	if p.APIKey == "" {
		return d.Err("missing api_key")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
