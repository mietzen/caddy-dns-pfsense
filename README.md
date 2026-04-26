# pfSense DNS module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It manages DNS records in [pfSense](https://www.pfsense.org/) Unbound via the pfSense REST API v2.
You can combine it with Caddy's dynamic DNS or DNS-01 ACME challenge to get valid TLS certs for internal domains.

> **Note:** Only A and AAAA records are supported.

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/mietzen/caddy-dns-pfsense)

## Caddy module name

```
dns.providers.pfsense
```

## Config examples

To use this module for internal domain DNS overrides, together with [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns):

```json
{
	"apps": {
		"dynamic_dns": {
			"dns_provider": {
				"name": "pfsense",
				"host": "{env.PFSENSE_HOSTNAME}",
				"api_key": "{env.PFSENSE_API_KEY}",
				"insecure": true,
				"entry_description": "Managed by Caddy"
			},
			"domains": {
				"example.com": [""]
			},
			"ip_sources": [
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"check_interval": "5m",
			"versions": {
				"ipv4": true,
				"ipv6": true
			},
			"ttl": "1h",
			"dynamic_domains": true
		}
	}
}
```

or with the Caddyfile:

```text
{
	dynamic_dns {
		provider pfsense {
			host {env.PFSENSE_HOSTNAME}
			api_key {env.PFSENSE_API_KEY}
			insecure true # Optional: skip TLS verification for self-signed certs
			entry_description "Managed by Caddy" # Optional
		}
		domains {
			example.com
		}
		dynamic_domains
		ip_source interface eth0
		check_interval 5m
		ttl 1h
	}
}
```

### Valid local TLS Certs

Here an example using porkbun, but you can use any of the available [caddy-dns](https://github.com/caddy-dns) providers for the ACME challenge:

```text
{
	dynamic_dns {
		provider pfsense {
			host {env.PFSENSE_HOSTNAME}
			api_key {env.PFSENSE_API_KEY}
			insecure true # Optional: skip TLS verification for self-signed certs
		}
		domains {
			example.com
		}
		dynamic_domains
		ip_source interface eth0
		check_interval 5m
		ttl 1h
	}
}

*.example.com {
	tls {
		dns porkbun {
			api_key {env.PORKBUN_API_KEY}
			api_secret_key {env.PORKBUN_API_SECRET_KEY}
		}
	}
	reverse_proxy localhost:8080
}
```

### Docker

```yaml
services:
  caddy:
    image: caddy-pfsense
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      PFSENSE_HOSTNAME: pfsense.example.com
      PFSENSE_API_KEY: your-api-key-here
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
```

### Docker service discovery

```text
{
	dynamic_dns {
		provider pfsense {
			host {env.PFSENSE_HOSTNAME}
			api_key {env.PFSENSE_API_KEY}
			insecure true
		}
		domains {
			example.com
		}
		dynamic_domains
		ip_source interface eth0
		check_interval 1m
	}
}
```

## Building with xcaddy

```
xcaddy build \
    --with github.com/mietzen/caddy-dns-pfsense \
    --with github.com/mholt/caddy-dynamicdns
```

## Setting up pfSense API key

1. Install the **pfSense-pkg-RESTAPI** package via **System → Package Manager → Available Packages**
2. Go to **System → REST API → Settings** and enable the API
3. Go to **System → REST API → Keys** and generate a new API key for your user
4. Grant the user/key appropriate permissions for the DNS Resolver (read + write access to `/api/v2/services/dns_resolver/*`)
5. Use the generated key as the `api_key` value in your Caddy configuration

The API key is sent as the `x-api-key` HTTP header on every request.
