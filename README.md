# ReconForge

Multi-engine, scope-filtered subdomain enumeration CLI written in Go. Inspired by SubWatch; this version is a one-shot enumeration pipeline rather than a notification daemon.

## Build / install

```bash
git clone https://github.com/YOUR_USERNAME/reconforge.git
cd reconforge
go install ./cmd/reconforge
export PATH="$(go env GOPATH)/bin:$PATH"
```

To enable `go install github.com/YOUR_USERNAME/reconforge/cmd/reconforge@latest`, replace the module path in go.mod with your actual public repository, commit, tag and push it. A repository must exist for remote Go installation.

Install external tools separately and ensure they are on PATH. Supported executables: subfinder, assetfinder, findomain, shosubgo, amass. Each is optional; missing tools are reported and skipped.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/owasp-amass/amass/v4/...@latest
# Install findomain and shosubgo using their upstream release/install instructions.
export PATH="$(go env GOPATH)/bin:$PATH"
export SHODAN_API_KEY='your_key'
reconforge -l domains.txt -o subs -c 8 -resolve
reconforge -l domains.txt -o subs -recursive -timeout 3m
```

Use only on domains in your authorized scope. Recursive mode is capped at two passes and 3000 next-pass targets. The Shosubgo CLI is invoked using `-d` and `-s`; check your installed version for flag compatibility. Output: `all_subs.txt`, per-engine text files, `results.json`, `results.csv`, and optionally `resolved.txt`. DNS resolving is opt-in; it may generate many DNS queries. Engines are run in parallel with timeouts. This tool does not perform active brute force, port scanning, or HTTP probing.
