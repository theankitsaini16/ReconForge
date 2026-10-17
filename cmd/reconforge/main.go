package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type record struct {
	Domain   string   `json:"domain"`
	Sources  []string `json:"sources"`
	Resolved bool     `json:"resolved"`
	IPs      []string `json:"ips,omitempty"`
}
type result struct {
	source string
	names  []string
	err    error
}

var valid = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func readLines(path string) ([]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 4*1024*1024)
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if v != "" && !strings.HasPrefix(v, "#") {
			out = append(out, v)
		}
	}
	return out, s.Err()
}
func writeLines(path string, a []string) error {
	return os.WriteFile(path, []byte(strings.Join(a, "\n")+"\n"), 0644)
}
func normalize(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "*.")
	v = strings.TrimSuffix(v, ".")
	return v
}
func inScope(v string, roots []string) bool {
	for _, r := range roots {
		if v == r || strings.HasSuffix(v, "."+r) {
			return true
		}
	}
	return false
}
func unique(a []string) []string {
	m := map[string]bool{}
	var o []string
	for _, v := range a {
		v = normalize(v)
		if valid.MatchString(v) && !m[v] {
			m[v] = true
			o = append(o, v)
		}
	}
	sort.Strings(o)
	return o
}
func execute(ctx context.Context, name string, args ...string) ([]string, error) {
	if _, e := exec.LookPath(name); e != nil {
		return nil, fmt.Errorf("%s not installed", name)
	}
	c := exec.CommandContext(ctx, name, args...)
	b, e := c.Output()
	if e != nil {
		return nil, fmt.Errorf("%s: %w", name, e)
	}
	return strings.Fields(string(b)), nil
}
func main() {
	input := flag.String("l", "domains.txt", "root domains file")
	out := flag.String("o", "subs", "output directory")
	engines := flag.String("tools", "subfinder,assetfinder,findomain,shosubgo,amass", "comma-separated engines")
	threads := flag.Int("c", 8, "parallel engine jobs")
	timeout := flag.Duration("timeout", 5*time.Minute, "timeout per engine job")
	dns := flag.Bool("resolve", false, "resolve DNS and export resolved names")
	recursive := flag.Bool("recursive", false, "second pass using discovered subdomains (passive engines)")
	depth := flag.Int("depth", 1, "maximum enumeration passes (1 or 2)")
	flag.Parse()
	roots, e := readLines(*input)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	roots = unique(roots)
	if len(roots) == 0 {
		fmt.Fprintln(os.Stderr, "no valid root domains")
		os.Exit(1)
	}
	if *threads < 1 {
		*threads = 1
	}
	if *recursive {
		*depth = 2
	}
	if *depth < 1 {
		*depth = 1
	}
	if *depth > 2 {
		*depth = 2
	}
	os.MkdirAll(*out, 0755)
	sources := strings.Split(*engines, ",")
	all := map[string]map[string]bool{}
	seen := map[string]bool{}
	targets := roots
	for pass := 0; pass < *depth; pass++ {
		type job struct{ tool, domain string }
		jobs := make(chan job)
		results := make(chan result, 128)
		var wg sync.WaitGroup
		for i := 0; i < *threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					ctx, cancel := context.WithTimeout(context.Background(), *timeout)
					var args []string
					switch j.tool {
					case "subfinder":
						args = []string{"-d", j.domain, "-silent", "-all"}
					case "assetfinder":
						args = []string{"--subs-only", j.domain}
					case "findomain":
						args = []string{"-t", j.domain, "-q"}
					case "shosubgo":
						args = []string{"-d", j.domain, "-s", os.Getenv("SHODAN_API_KEY")}
						if os.Getenv("SHODAN_API_KEY") == "" {
							results <- result{j.tool, nil, fmt.Errorf("SHODAN_API_KEY not set")}
							cancel()
							continue
						}
					case "amass":
						args = []string{"enum", "-passive", "-d", j.domain}
					default:
						results <- result{j.tool, nil, fmt.Errorf("unknown engine")}
						cancel()
						continue
					}
					names, err := execute(ctx, j.tool, args...)
					cancel()
					results <- result{j.tool, names, err}
				}
			}()
		}
		go func() {
			for _, d := range targets {
				for _, src := range sources {
					src = strings.TrimSpace(src)
					if src != "" {
						jobs <- job{src, d}
					}
				}
			}
			close(jobs)
			wg.Wait()
			close(results)
		}()
		next := []string{}
		for r := range results {
			if r.err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", r.source, r.err)
				continue
			}
			count := 0
			for _, name := range r.names {
				name = normalize(name)
				if !valid.MatchString(name) || !inScope(name, roots) {
					continue
				}
				if all[name] == nil {
					all[name] = map[string]bool{}
					next = append(next, name)
				}
				all[name][r.source] = true
				count++
			}
			fmt.Printf("[+] %s: %d scoped results\n", r.source, count)
		}
		for _, d := range targets {
			seen[d] = true
		}
		targets = nil
		for _, d := range unique(next) {
			if !seen[d] {
				targets = append(targets, d)
			}
		}
		if len(targets) > 3000 {
			targets = targets[:3000]
		}
		if len(targets) == 0 {
			break
		}
	}
	names := make([]string, 0, len(all))
	per := map[string][]string{}
	for d, ss := range all {
		names = append(names, d)
		for s := range ss {
			per[s] = append(per[s], d)
		}
	}
	sort.Strings(names)
	for s, ds := range per {
		sort.Strings(ds)
		writeLines(filepath.Join(*out, s+"_domains.txt"), ds)
	}
	writeLines(filepath.Join(*out, "all_subs.txt"), names)
	records := make([]record, 0, len(names))
	resolved := []string{}
	for _, d := range names {
		ss := []string{}
		for s := range all[d] {
			ss = append(ss, s)
		}
		sort.Strings(ss)
		r := record{Domain: d, Sources: ss}
		if *dns {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			ips, e := net.DefaultResolver.LookupHost(ctx, d)
			cancel()
			if e == nil && len(ips) > 0 {
				r.Resolved = true
				r.IPs = ips
				resolved = append(resolved, d)
			}
		}
		records = append(records, r)
	}
	if *dns {
		writeLines(filepath.Join(*out, "resolved.txt"), resolved)
	}
	b, _ := json.MarshalIndent(records, "", "  ")
	os.WriteFile(filepath.Join(*out, "results.json"), b, 0644)
	f, e := os.Create(filepath.Join(*out, "results.csv"))
	if e == nil {
		w := csv.NewWriter(f)
		w.Write([]string{"domain", "sources", "resolved", "ips"})
		for _, r := range records {
			w.Write([]string{r.Domain, strings.Join(r.Sources, ";"), fmt.Sprint(r.Resolved), strings.Join(r.IPs, ";")})
		}
		w.Flush()
		f.Close()
	}
	fmt.Printf("\nDone: %d unique subdomains in %s\n", len(names), *out)
}
