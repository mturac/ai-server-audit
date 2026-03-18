// ================================================================
//  ai-server-audit CLI — Go Wrapper
//  Calls Rust core via cgo for all heavy lifting.
//  Zero external dependencies — pure stdlib.
// ================================================================

package main

/*
#cgo LDFLAGS: -L../core/target/release -laudit_core -ldl -lpthread -lm
#include <stdlib.h>

char* audit_scan_ports(const char* host, const char* ports_json, unsigned long long timeout_ms, unsigned int threads);
char* audit_health_check(const char* host, unsigned short port, const char* label, unsigned long long timeout_ms);
char* audit_security_checks(const char* host, unsigned long long timeout_ms);
char* audit_check_updates();
void  audit_free_string(char* ptr);
*/
import "C"

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"
)

// ── Config ───────────────────────────────────────────────────────

type Config struct {
	Server struct {
		Host        string `json:"host"`
		TimeoutMs   uint64 `json:"timeout_ms"`
		ScanThreads uint32 `json:"scan_threads"`
	} `json:"server"`
	Ports struct {
		Scan      []uint16 `json:"scan"`
		Forbidden []uint16 `json:"forbidden"`
	} `json:"ports"`
	Checks struct {
		HealthCheck bool `json:"health_check"`
		PortScan    bool `json:"port_scan"`
		Security    bool `json:"security"`
		Updates     bool `json:"updates"`
	} `json:"checks"`
	AI struct {
		Anthropic       bool   `json:"anthropic"`
		OpenAI          bool   `json:"openai"`
		AnthropicAPIKey string `json:"anthropic_api_key"`
		OpenAIAPIKey    string `json:"openai_api_key"`
	} `json:"ai"`
	Output struct {
		Format     string `json:"format"`
		ReportFile string `json:"report_file"`
	} `json:"output"`
	Notify struct {
		WebhookURL string `json:"webhook_url"`
	} `json:"notify"`
}

func defaultConfig() Config {
	var cfg Config
	cfg.Server.Host        = "127.0.0.1"
	cfg.Server.TimeoutMs   = 1500
	cfg.Server.ScanThreads = 50
	cfg.Ports.Scan         = []uint16{21, 22, 23, 25, 53, 80, 110, 143, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9200, 27017}
	cfg.Ports.Forbidden    = []uint16{23, 21, 110, 143}
	cfg.Checks.HealthCheck = true
	cfg.Checks.PortScan    = true
	cfg.Checks.Security    = true
	cfg.Checks.Updates     = true
	cfg.AI.Anthropic       = true
	cfg.AI.OpenAI          = true
	cfg.Output.Format      = "pretty"
	return cfg
}

// ── CheckResult (mirrors Rust types) ─────────────────────────────

type CheckResult struct {
	Category  string   `json:"category"`
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Message   string   `json:"message"`
	LatencyMs *uint64  `json:"latency_ms"`
	Details   []string `json:"details"`
}

type AuditReport struct {
	Host      string        `json:"host"`
	Timestamp string        `json:"timestamp"`
	ElapsedMs int64         `json:"elapsed_ms"`
	Total     int           `json:"total"`
	Ok        int           `json:"ok"`
	Warning   int           `json:"warning"`
	Critical  int           `json:"critical"`
	Info      int           `json:"info"`
	Results   []CheckResult `json:"results"`
}

func (r *AuditReport) Add(results []CheckResult) {
	for _, cr := range results {
		switch cr.Status {
		case "Ok":       r.Ok++
		case "Warning":  r.Warning++
		case "Critical": r.Critical++
		case "Info":     r.Info++
		}
		r.Total++
		r.Results = append(r.Results, cr)
	}
}

func (r *AuditReport) HasCritical() bool { return r.Critical > 0 }

// ── Rust FFI Helpers ─────────────────────────────────────────────

func rustScanPorts(host string, ports []uint16, timeoutMs uint64, threads uint32) []CheckResult {
	portsJSON, _ := json.Marshal(ports)
	cHost  := C.CString(host)
	cPorts := C.CString(string(portsJSON))
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPorts))

	raw := C.audit_scan_ports(cHost, cPorts, C.ulonglong(timeoutMs), C.uint(threads))
	defer C.audit_free_string(raw)

	var results []CheckResult
	json.Unmarshal([]byte(C.GoString(raw)), &results)
	return results
}

func rustHealthCheck(host string, port uint16, label string, timeoutMs uint64) CheckResult {
	cHost  := C.CString(host)
	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cLabel))

	raw := C.audit_health_check(cHost, C.ushort(port), cLabel, C.ulonglong(timeoutMs))
	defer C.audit_free_string(raw)

	var result CheckResult
	json.Unmarshal([]byte(C.GoString(raw)), &result)
	return result
}

func rustSecurityChecks(host string, timeoutMs uint64) []CheckResult {
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	raw := C.audit_security_checks(cHost, C.ulonglong(timeoutMs))
	defer C.audit_free_string(raw)

	var results []CheckResult
	json.Unmarshal([]byte(C.GoString(raw)), &results)
	return results
}

func rustCheckUpdates() []CheckResult {
	raw := C.audit_check_updates()
	defer C.audit_free_string(raw)

	var results []CheckResult
	json.Unmarshal([]byte(C.GoString(raw)), &results)
	return results
}

// ── Terminal Output ───────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
)

func colorStatus(s string) string {
	switch s {
	case "Ok":       return green + "✅ OK  " + reset
	case "Warning":  return yellow + "⚠  WARN" + reset
	case "Critical": return red + "🔴 CRIT" + reset
	default:         return dim + "ℹ  INFO" + reset
	}
}

func printBanner() {
	fmt.Println()
	fmt.Println(cyan + "  ┌──────────────────────────────────────────────────┐" + reset)
	fmt.Println(cyan + "  │  🦀 + 🐹  AI Server Audit  ·  Rust Core + Go CLI │" + reset)
	fmt.Println(cyan + "  │     Anthropic Claude  &  OpenAI  ·  v0.1.0       │" + reset)
	fmt.Println(cyan + "  └──────────────────────────────────────────────────┘" + reset)
	fmt.Println()
}

func printCategory(cat string, results []CheckResult) {
	var filtered []CheckResult
	for _, r := range results {
		if r.Category == cat {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) == 0 {
		return
	}

	fmt.Printf("  %s▶%s %s%s%s\n", cyan, reset, bold, cat, reset)
	fmt.Println(dim + "  " + strings.Repeat("─", 72) + reset)

	for _, r := range filtered {
		lat := "—"
		if r.LatencyMs != nil {
			lat = fmt.Sprintf("%dms", *r.LatencyMs)
		}
		fmt.Printf("  %s  %-24s  %-40s  %s\n",
			colorStatus(r.Status),
			bold+r.Name+reset,
			r.Message,
			dim+lat+reset,
		)
		if r.Status != "Ok" && r.Status != "Info" {
			for _, d := range r.Details {
				fmt.Printf("                %s· %s%s\n", dim, d, reset)
			}
		}
	}
	fmt.Println()
}

func printSummary(report *AuditReport) {
	printBanner()
	fmt.Printf("  %sTarget:%s %s%s%s   %s%s%s\n\n",
		bold, reset,
		cyan+bold, report.Host, reset,
		dim, report.Timestamp, reset)

	for _, cat := range []string{"Health", "Ports", "Security", "Updates"} {
		printCategory(cat, report.Results)
	}

	fmt.Println(dim + "  " + strings.Repeat("─", 72) + reset)
	fmt.Printf("  %s✅ %s%s  %s⚠  %s%s  %s🔴 %s%s  %sℹ  %s%s  │  %d checks  │  %dms\n\n",
		green, fmt.Sprint(report.Ok), reset,
		yellow, fmt.Sprint(report.Warning), reset,
		red, fmt.Sprint(report.Critical), reset,
		dim, fmt.Sprint(report.Info), reset,
		report.Total, report.ElapsedMs,
	)

	if report.Critical > 0 {
		fmt.Printf("  %s%s⚠  %d critical issue(s) — immediate action recommended!%s\n\n",
			bold, red, report.Critical, reset)
	} else if report.Warning > 0 {
		fmt.Printf("  %s!  %d warning(s) — review recommended%s\n\n",
			yellow, report.Warning, reset)
	} else {
		fmt.Printf("  %s%s✓  All checks passed — server looks healthy!%s\n\n",
			bold, green, reset)
	}
}

// ── Init Config ──────────────────────────────────────────────────

func cmdInit() {
	const path = "audit.json"
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "%s✗%s %s already exists\n", red, reset, path)
		os.Exit(1)
	}
	cfg := defaultConfig()
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(path, b, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s✓%s Created %s — edit it then run: ai-server-audit run\n", green, reset, path)
}

// ── Main ──────────────────────────────────────────────────────────

func main() {
	runCmd      := flag.NewFlagSet("run",      flag.ExitOnError)
	healthCmd   := flag.NewFlagSet("health",   flag.ExitOnError)
	portsCmd    := flag.NewFlagSet("ports",    flag.ExitOnError)
	securityCmd := flag.NewFlagSet("security", flag.ExitOnError)
	updatesCmd  := flag.NewFlagSet("updates",  flag.ExitOnError)

	configPath := runCmd.String("config", "audit.json", "Path to config file")
	hostFlag   := runCmd.String("host",   "",           "Override target host")
	outputFmt  := runCmd.String("output", "pretty",     "Output format: pretty | json")
	reportFile := runCmd.String("report", "",           "Save JSON report to file")

	for _, fs := range []*flag.FlagSet{healthCmd, portsCmd, securityCmd, updatesCmd} {
		fs.String("config", "audit.json", "Path to config file")
		fs.String("host",   "",           "Override target host")
		fs.String("output", "pretty",     "Output format: pretty | json")
		fs.String("report", "",           "Save JSON report to file")
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [flags]\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "Commands: init | run | health | ports | security | updates\n")
		fmt.Fprintf(os.Stderr, "Example:  %s run --host 10.0.0.1\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	sub := os.Args[1]
	if sub == "init" {
		cmdInit()
		return
	}

	switch sub {
	case "run":      runCmd.Parse(os.Args[2:])
	case "health":   healthCmd.Parse(os.Args[2:])
	case "ports":    portsCmd.Parse(os.Args[2:])
	case "security": securityCmd.Parse(os.Args[2:])
	case "updates":  updatesCmd.Parse(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", sub)
		os.Exit(1)
	}

	cfg := defaultConfig()
	if data, err := os.ReadFile(*configPath); err == nil {
		json.Unmarshal(data, &cfg)
	}
	if *hostFlag != "" {
		cfg.Server.Host = *hostFlag
	}

	start := time.Now()
	report := AuditReport{
		Host:      cfg.Server.Host,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	runAll      := sub == "run"
	runHealth   := runAll || sub == "health"
	runPorts    := runAll || sub == "ports"
	runSecurity := runAll || sub == "security"
	runUpdates  := runAll || sub == "updates"

	if runHealth && cfg.Checks.HealthCheck {
		fmt.Fprintf(os.Stderr, "%s⠋%s Checking AI provider health…\r", cyan, reset)
		if cfg.AI.Anthropic {
			r := rustHealthCheck("api.anthropic.com", 443, "Anthropic Claude", cfg.Server.TimeoutMs)
			report.Add([]CheckResult{r})
		}
		if cfg.AI.OpenAI {
			r := rustHealthCheck("api.openai.com", 443, "OpenAI", cfg.Server.TimeoutMs)
			report.Add([]CheckResult{r})
		}
		fmt.Fprint(os.Stderr, "                                    \r")
	}

	if runPorts && cfg.Checks.PortScan {
		fmt.Fprintf(os.Stderr, "%s⠙%s Scanning %d ports on %s…\r", cyan, reset, len(cfg.Ports.Scan), cfg.Server.Host)
		results := rustScanPorts(cfg.Server.Host, cfg.Ports.Scan, cfg.Server.TimeoutMs, cfg.Server.ScanThreads)
		report.Add(results)
		fmt.Fprint(os.Stderr, "                                                    \r")
	}

	if runSecurity && cfg.Checks.Security {
		fmt.Fprintf(os.Stderr, "%s⠹%s Running security checks…\r", cyan, reset)
		results := rustSecurityChecks(cfg.Server.Host, cfg.Server.TimeoutMs)
		report.Add(results)
		fmt.Fprint(os.Stderr, "                                    \r")
	}

	if runUpdates && cfg.Checks.Updates {
		fmt.Fprintf(os.Stderr, "%s⠸%s Checking for updates…\r", cyan, reset)
		results := rustCheckUpdates()
		report.Add(results)
		fmt.Fprint(os.Stderr, "                                    \r")
	}

	report.ElapsedMs = time.Since(start).Milliseconds()

	switch *outputFmt {
	case "json":
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
	default:
		printSummary(&report)
	}

	savePath := *reportFile
	if savePath == "" {
		savePath = cfg.Output.ReportFile
	}
	if savePath != "" {
		b, _ := json.MarshalIndent(report, "", "  ")
		os.WriteFile(savePath, b, 0644)
		fmt.Printf("  %sReport saved ->%s %s%s%s\n", dim, reset, cyan, savePath, reset)
	}

	if report.HasCritical() {
		os.Exit(1)
	}
}
