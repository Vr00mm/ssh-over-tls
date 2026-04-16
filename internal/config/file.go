package config

import (
	"bufio"
	"os"
	"strings"
)

// loadFile reads key=value pairs from a file and returns them as a map.
// A missing file is silently ignored; any other read error is returned.
func loadFile(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is user-controlled only via CONFIG_FILE env var
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	defer f.Close() //nolint:errcheck // read-only file, close error not actionable

	vars := make(map[string]string)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if parseLine(line, vars) {
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return vars, nil
}

// parseLine parses a single configuration line into the vars map.
// Returns true if the line was handled (blank, comment, or valid key=value).
func parseLine(line string, vars map[string]string) bool {
	// Skip blank lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return true
	}

	// Parse key=value
	before, after, found := strings.Cut(line, "=")
	if !found {
		return true // Silently skip malformed lines
	}

	key := strings.TrimSpace(before)
	value := strings.TrimSpace(after)

	if key != "" {
		vars[key] = value
	}

	return true
}
