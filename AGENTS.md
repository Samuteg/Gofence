# AGENTS.md

Offensive security CLI written in Go. Single pure-Go binary with embedded assets, local SQLite storage, TUI/headless modes, and strict in-scope network checks.

## Key Commands

- **Build binary**: `go build -o gofence .`
- **Build portable static binary (no CGO)**: `CGO_ENABLED=0 go build -ldflags '-s -w' -o gofence .`
- **Run all tests**: `go test ./...`
- **Run a single package**: `go test ./internal/surface`
- **Run a focused test**: `go test -v ./internal/surface -run TestFuzzer`
- **Static analysis**: `go vet ./...` (must be clean — IPv6 addresses via `net.JoinHostPort`)
- **Build with version**: `make build` or `make static` (injects version/commit via ldflags)

## Core Architecture & Directory Responsibilities

- `main.go` -> `cmd/`: Cobra CLI commands, flags, output formatting, and command handlers.
- `cmd/helpers.go`: Shared CLI persistence helpers (`openWorkspace`), target parsing (`hostOf`), and temporary wordlist generation.
- `internal/data/`: SQLite interface (`modernc.org/sqlite`, pure Go), schema migrations, KV store, workspace/host/port/finding persistence, and scope queries.
- `internal/assets/`: Embedded wordlists (`paths.txt`, `subdomains.txt`) and vulnerability templates (`exposed-aws.yaml`, `exposed-git.yaml`) via `go:embed`.
- `internal/recon/`: Network discovery (DNS bruteforce/AXFR, OSINT API clients, TCP/UDP port scanner).
- `internal/surface/`: Web attack surface mapping (fuzzer with streaming wordlists, TLS inspector, AST crawler with secret detection, Nuclei-compatible YAML vuln engine).
- `internal/exploit/`: Reverse/bind payload generators, multi-handler listener (`sync.Map` session tracking), dictionary brute-forcer with backoff.
- `internal/ux/`: Bubbletea TUI, headless pipe detection, rate limiter profiles (`sneaky`, `normal`, `aggressive`), and WAF detector with backoff.
- `pkg/httpclient/`: Centralized HTTP client configured from env/config.

## Critical Gotchas & Constraints

1. **Pure Go / CGO**: `modernc.org/sqlite` is used so CGO is unnecessary. Keep builds CGO-free when producing static binaries.
2. **ScopeGuard Enforcement**: All network scans MUST respect active workspace scope. Out-of-scope targets are dropped with stderr logs (`Out-of-Scope Blocked`).
3. **Embedded Fallbacks**: `dns`, `fuzz`, and `vulns` fall back to embedded assets in `internal/assets/` when user-supplied wordlist (`-w`) or template (`-t`) flags are omitted.
4. **Workspace Persistence**: Commands persist findings best-effort when a workspace is active (either specified via `--workspace` or stored in KV `active_workspace`). Persistence failure produces stderr warnings without failing execution.
5. **CLI Output Discipline**:
   - `stdout`: Pure structured data or command output for UNIX pipelines.
   - `stderr`: Status messages, progress, WAF hit warnings, and persisted count logs.
6. **Spec-Anchored Verification**: Workflow specs live in `.spec/features/gofence-cli/` with rules in `.spec/constituicao.md`.
