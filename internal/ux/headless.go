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
	var lines []string
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
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

func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
