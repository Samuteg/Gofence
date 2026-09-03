package ux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type OutputMode int

const (
	OutputAuto OutputMode = iota
	OutputJSON
	OutputPlain
)

func DetectOutputMode(forceJSON bool) OutputMode {
	if forceJSON {
		return OutputJSON
	}
	if !isatty(os.Stdout) {
		return OutputJSON
	}
	return OutputPlain
}

func PrintJSON(data interface{}) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func PrintPlain(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func PipeInput() ([]string, error) {
	if isatty(os.Stdin) {
		return nil, nil
	}
	return PipeLines(os.Stdin)
}

// PipeLines reads non-empty trimmed lines from r.
func PipeLines(r io.Reader) ([]string, error) {
	var lines []string
	reader := bufio.NewReader(r)
	for {
		line, err := reader.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimSpace(line))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return lines, err
		}
	}
	return lines, nil
}

// StdinPiped reports whether stdin carries piped input.
func StdinPiped() bool {
	return !isatty(os.Stdin)
}

// ResolveTarget picks the network target: an explicit arg wins; otherwise
// the first whitespace-separated field of the first non-empty stdin line.
// It returns the target, how many extra lines were ignored, or an error
// when there is neither arg nor piped input.
func ResolveTarget(args []string, stdin io.Reader, piped bool) (string, int, error) {
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		return args[0], 0, nil
	}
	if !piped {
		return "", 0, fmt.Errorf("target required as argument or piped stdin")
	}
	lines, err := PipeLines(stdin)
	if err != nil {
		return "", 0, err
	}
	if len(lines) == 0 {
		return "", 0, fmt.Errorf("empty piped stdin: no target found")
	}
	return strings.Fields(lines[0])[0], len(lines) - 1, nil
}

func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
