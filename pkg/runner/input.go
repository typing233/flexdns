package runner

import (
	"bufio"
	"os"
	"strings"
)

func readFromStdin() <-chan string {
	ch := make(chan string, 128)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				ch <- line
			}
		}
	}()
	return ch
}

func readFromWordlist(path string, domain string) (<-chan string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	ch := make(chan string, 128)
	go func() {
		defer close(ch)
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word != "" {
				ch <- word + "." + domain
			}
		}
	}()
	return ch, nil
}

func loadResolvers(addresses []string, filePath string) ([]string, error) {
	seen := make(map[string]struct{})
	var result []string

	for _, addr := range addresses {
		for _, a := range strings.Split(addr, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				if _, ok := seen[a]; !ok {
					seen[a] = struct{}{}
					result = append(result, a)
				}
			}
		}
	}

	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			a := strings.TrimSpace(scanner.Text())
			if a != "" && !strings.HasPrefix(a, "#") {
				if _, ok := seen[a]; !ok {
					seen[a] = struct{}{}
					result = append(result, a)
				}
			}
		}
	}

	if len(result) == 0 {
		result = []string{"8.8.8.8", "1.1.1.1"}
	}
	return result, nil
}
