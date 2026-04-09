# certbot-dns-vipdns

Certbot DNS authenticator plugin for [VipDNS](https://vipdns.nl).

Automates DNS-01 challenges by creating and removing `_acme-challenge` TXT records
via the VipDNS LetsEncrypt API.

## Installation

```bash
pip install certbot-dns-vipdns
```

## Usage

### With a credentials file (recommended)

```bash
certbot certonly \
  --authenticator dns-vipdns \
  --dns-vipdns-credentials /etc/letsencrypt/vipdns.ini \
  -d example.com
```

The `--dns-vipdns-credentials` flag accepts INI, JSON, and YAML files (detected by extension).
The API URL defaults to `https://vipdns.nl` and can be omitted from any credentials file.

Secure the file after creation:

```bash
chmod 600 /etc/letsencrypt/vipdns.ini
```

---

#### INI (`.ini`)

```ini
dns_vipdns_api_token = your-token-here
```

With explicit URL:

```ini
dns_vipdns_api_url = https://vipdns.nl
dns_vipdns_api_token = your-token-here
```

---

#### JSON (`.json`)

```json
{
  "api_token": "your-token-here"
}
```

With explicit URL:

```json
{
  "api_url": "https://vipdns.nl",
  "api_token": "your-token-here"
}
```

---

#### YAML (`.yaml` / `.yml`)

```yaml
api_token: your-token-here
```

With explicit URL:

```yaml
api_url: https://vipdns.nl
api_token: your-token-here
```

---

### With CLI flags

Credentials can also be passed directly as flags without a credentials file:

```bash
certbot certonly \
  --authenticator dns-vipdns \
  --dns-vipdns-api-token your-token \
  -d example.com
```

Override the API URL if needed:

```bash
certbot certonly \
  --authenticator dns-vipdns \
  --dns-vipdns-api-url https://vipdns.nl \
  --dns-vipdns-api-token your-token \
  -d example.com
```

## Automatic renewal

Certbot stores the flags used during `certonly` in a renewal configuration file under
`/etc/letsencrypt/renewal/example.com.conf`, so subsequent `certbot renew` calls reuse
them automatically, so no extra configuration is needed.

### Systemd (recommended)

Most modern Linux distributions ship a `certbot.timer` systemd unit that runs
`certbot renew` twice a day. Check whether it is active:

```bash
systemctl status certbot.timer
```

Enable and start it if it is not running:

```bash
systemctl enable --now certbot.timer
```

### Cron

If systemd is not available, add a cron job:

```bash
crontab -e
```

```cron
0 3 * * * certbot renew --quiet
```

This runs renewal checks daily at 03:00. Certbot only renews certificates that expire
within 30 days, so running it daily is safe.

### Reloading services after renewal

Use the `--deploy-hook` flag to reload your web server after a successful renewal:

```bash
certbot certonly \
  --authenticator dns-vipdns \
  --dns-vipdns-credentials /etc/letsencrypt/vipdns.ini \
  --deploy-hook "systemctl reload nginx" \
  -d example.com
```

The hook is saved in the renewal config and runs automatically on every successful renewal.

## Token requirements

The API token must be a `LetsEncrypt`-type token with the `letsencrypt:write` scope,
scoped to the DNS zone(s) you are requesting certificates for.

Tokens can be created in the VipDNS portal under **Settings → API tokens**.

## Wildcard certificates

Wildcard domains are supported. The `*.` prefix is automatically stripped when calling
the API:

```bash
certbot certonly \
  --authenticator dns-vipdns \
  --dns-vipdns-credentials /etc/letsencrypt/vipdns.ini \
  -d "*.example.com"
```
