# ReconForge

**ReconForge** is a Go-based, multi-source subdomain enumeration and monitoring CLI. It aggregates passive discoveries, deduplicates and filters by root-domain scope, optionally resolves DNS, tracks previously discovered names across runs, and notifies a Discord channel when new names appear. Designed for **authorized security testing** and asset inventory.

## Features

- Sources: **crt.sh (native HTTPS)**, **Subfinder**, **Assetfinder**, **Amass (passive)**, **Findomain**, **Shosubgo** (Shodan).
- Parallel engine execution, timeouts, optional second-pass recursive discovery, scope filtering.
- TXT per-source exports, combined TXT, JSON, CSV, optional DNS resolution.
- Persistent `state.json` history, `new_subdomains.txt`, Discord webhook alerts.
- **Every 6 hours** with cron (recommended) or built-in `-loop -interval 6h`.
- First run establishes a baseline without alerting by default; add `-alert-baseline` to notify for initial discoveries.
- Scan lock prevents overlapping invocations using the same output directory on Linux.

> **Scope:** Only run on domains you own or are explicitly authorized to assess. Results may contain historical names, not necessarily active services. The first run is not a historical change detector: it starts tracking changes from that moment onward.

## Requirements

- Linux (including Kali or VPS), Go **1.21+** for building. Cron is optional if using `-loop`.
- Network access to crt.sh, optional enumeration providers and Discord.
- `crtsh` is **built in** and requires no external binary or API key.
- Optional binaries, each available in `$PATH`:

| Engine | Install / reference | Credentials |
|---|---|---|
| Subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Configure provider API keys for richer results, see below |
| Assetfinder | `go install github.com/tomnomnom/assetfinder@latest` | None required |
| Amass | [OWASP Amass](https://github.com/owasp-amass/amass) releases/package manager; `amass` on PATH | Optional config.ini for API-backed sources |
| Findomain | [Findomain](https://github.com/Findomain/Findomain) releases; `findomain` on PATH | Optional provider configuration |
| Shosubgo | Install the `shosubgo` binary from its upstream repository; `shosubgo` on PATH | `SHODAN_API_KEY` |

ReconForge **skips failed/missing engines**, printing a warning; other engines continue. Some external tools may change CLI flags between releases; use compatible upstream versions. Amass config format depends on your Amass version.

## Install ReconForge

```bash
# Install published repository (once pushed to GitHub with this go.mod and directory layout)
go install github.com/theankitsaini16/ReconForge/cmd/reconforge@latest
export PATH="$(go env GOPATH)/bin:$PATH"
reconforge -version
```

Alternatively, build locally:

```bash
git clone https://github.com/theankitsaini16/ReconForge.git
cd ReconForge
go build -o reconforge ./cmd/reconforge
sudo install -m 0755 reconforge /usr/local/bin/reconforge
```

**If you are using Kali as `root`,** `go install` installs to `/root/go/bin` by default. Prefer running the monitor as a dedicated non-root user and ensure its Go binary directory is on PATH. External enumeration binaries must be accessible to the same user.

## Prepare target domains

Create `domains.txt`, one root domain per line (comments supported):

```text
example.com
example.org
# Add only authorized domains
```

## First scan

```bash
reconforge -l domains.txt -o subs -recursive -resolve
```

Specify engines explicitly if you want a subset:

```bash
reconforge -l domains.txt -o subs -tools crtsh,subfinder,assetfinder,amass,findomain,shosubgo -c 6 -timeout 3m
```

`-recursive` adds one additional enumeration pass on up to 100 discovered subdomains by default. This can significantly increase API usage and scan time. Set `-max-recursive 20` for a smaller run. DNS resolution is optional (`-resolve`).

## API configuration for public users

**Never commit API keys, webhook URLs, `.env`, or credential-bearing Amass/Subfinder configs to GitHub.** The `.gitignore` excludes `.env` and `subs/` by default. If a secret was exposed, rotate it immediately.

### Shodan / Shosubgo

1. Create an account at [Shodan](https://account.shodan.io/) and find your API key in your account settings (availability/quotas depend on your plan).
2. Export it in the shell that runs ReconForge:

   ```bash
   export SHODAN_API_KEY='YOUR_SHODAN_API_KEY'
   ```

3. Check `command -v shosubgo`; the tool invokes `shosubgo -d example.com -s "$SHODAN_API_KEY"` for each root domain.
4. Without a key, omit `shosubgo` from `-tools`; the remaining sources still run.

### Subfinder

1. Install Subfinder.
2. Obtain provider keys from providers you choose to use (e.g., SecurityTrails, Shodan, Censys), according to their own account instructions.
3. Use Subfinder's provider configuration, typically `~/.config/subfinder/provider-config.yaml` (check your installed version's documentation).
4. Set keys there **on the VPS**, with restrictive permissions (e.g., `chmod 600 ~/.config/subfinder/provider-config.yaml`). ReconForge does not read or store these keys.

### Amass

1. Install Amass and verify `amass enum -h`.
2. Configure API sources using the config format for your installed Amass release; for versions supporting it, use `~/.config/amass/config.ini`.
3. Run `reconforge -amass-config /home/USER/.config/amass/config.ini ...` if applicable. Otherwise omit `-amass-config`.
4. Amass runs with `enum -passive`, not active brute forcing.

### crt.sh

ReconForge uses `https://crt.sh/?q=%25.example.com&output=json`, **not** `crt.name/v1/search`. crt.sh can occasionally be slow or unavailable; failures are logged and other engines continue. Certificate transparency records can be stale.

## Discord webhook setup (step by step)

1. Open Discord and select a server where you can manage webhooks.
2. Open **Server Settings → Integrations → Webhooks** (or a channel's integrations settings, depending on the Discord UI).
3. Select **New Webhook**, give it a name such as `ReconForge`, choose the notification channel, and select **Copy Webhook URL**.
4. On your VPS, **do not paste this URL into GitHub or a public script**. Save it in a private environment file:

   ```bash
   sudo mkdir -p /etc/reconforge
   sudo nano /etc/reconforge/reconforge.env
   ```

   Contents (replace placeholders):

   ```bash
   DISCORD_WEBHOOK='https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN'
   SHODAN_API_KEY='YOUR_SHODAN_API_KEY'
   ```

   Restrict permissions, and ensure the user executing the job can read it:

   ```bash
   sudo chmod 600 /etc/reconforge/reconforge.env
   ```

5. In your terminal, load the secrets and run a scan:

   ```bash
   set -a
   . /etc/reconforge/reconforge.env
   set +a
   reconforge -l domains.txt -o subs -monitor
   ```

   The first run establishes a baseline and normally **does not send a Discord message**. On subsequent runs, only newly discovered subdomains trigger notifications. For an initial notification, add `-alert-baseline` **on the first run**.

A Discord webhook URL **contains its own secret token**; you do not need a separate Discord bot token. If it leaks, delete/recreate the webhook. Discord rate limits apply. ReconForge batches messages and retries transient failures, but delivery is best-effort; a failed webhook does not erase the local discovery file.

## Schedule every 6 hours (recommended: cron)

Install the binary to `/usr/local/bin/reconforge`. Place your target list at `/opt/reconforge/domains.txt`, and create a writable results directory. Ensure the cron user has access to the tools and secrets. Create a wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:/home/recon/go/bin"
set -a
source /etc/reconforge/reconforge.env
set +a
exec /usr/local/bin/reconforge \
  -l /opt/reconforge/domains.txt \
  -o /opt/reconforge/subs \
  -monitor -recursive -resolve \
  -c 6 -timeout 3m
```

Save as `/opt/reconforge/run.sh`, `chmod 700 /opt/reconforge/run.sh`, and ensure the script and secrets are readable by the chosen user. Then `crontab -e` as that user:

```cron
0 */6 * * * /opt/reconforge/run.sh >> /opt/reconforge/reconforge.log 2>&1
```

This starts scans at 00:00, 06:00, 12:00, and 18:00 **VPS local time**. The lock avoids overlapping scans, and cron logs should be rotated. If you install external tools in another location, adjust PATH. If the cron user cannot read `/etc/reconforge/reconforge.env`, grant that user appropriate read access rather than running everything as root.

### Alternative: continuously running service

```bash
reconforge -l /opt/reconforge/domains.txt -o /opt/reconforge/subs -monitor -loop -interval 6h
```

The interval is measured **after each scan completes**, unlike cron's fixed clock times. For production use, supervise it with systemd. **Do not run cron and loop mode simultaneously** against the same output directory.

## Output

```text
subs/
  crtsh_domains.txt
  subfinder_domains.txt
  assetfinder_domains.txt
  amass_domains.txt
  findomain_domains.txt
  shosubgo_domains.txt
  all_subs.txt
  resolved.txt           # if -resolve
  results.json
  results.csv
  new_subdomains.txt     # if -monitor; latest run only
  state.json              # if -monitor; persistent history
  .reconforge.lock
```

`state.json` contains all previously observed names, including ones that disappear from later scans. Keep it between runs; deleting it resets the baseline. Results are sorted and scope-filtered. Missing sources produce empty per-engine files, so stale results do not linger in those files.

## Options

```text
-l FILE             input file (default domains.txt)
-o DIR              output directory (default subs)
-tools LIST         comma-separated engine names
-c N                parallel jobs (default 6)
-timeout 3m         timeout per engine/domain job
-recursive          perform one extra pass
-max-recursive N    cap extra pass targets (default 100)
-resolve            DNS resolve names
-amass-config FILE  optional Amass configuration
-monitor            enable persistent change tracking
-state FILE         persistent history path (default <output>/state.json)
-webhook URL        webhook override (prefer DISCORD_WEBHOOK environment)
-alert-baseline     alert on initial scan
-loop               repeat indefinitely; implies -monitor
-interval 6h        delay after scan completes in loop mode
-version            print version
```

## Troubleshooting

- **`shosubgo: command not found`**: Add `$(go env GOPATH)/bin` to PATH for the user executing ReconForge, or install the binary to `/usr/local/bin`.
- **No Discord alert**: First run is baseline-only by default; confirm `DISCORD_WEBHOOK` is available to the cron process and that new names appeared. Inspect `new_subdomains.txt` and logs.
- **No subdomains**: Check internet connectivity, engine installation, API quotas, root-domain spelling, and stderr warnings. Some tools yield no results for some domains.
- **`another scan is running`**: A previous process holds the lock. Wait for it to finish; don't run concurrent scans with the same output directory.
- **GitHub install fails**: Confirm this code was pushed with the correct `go.mod` module path, and a reachable tag/commit exists.

## License

MIT. See `LICENSE`.
