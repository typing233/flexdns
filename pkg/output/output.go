package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Record struct {
	Domain    string   `json:"domain"`
	Type      string   `json:"type"`
	Resolver  string   `json:"resolver"`
	Protocol  string   `json:"protocol"`
	Answers   []string `json:"answers"`
	Timestamp string   `json:"timestamp"`
}

type Writer struct {
	jsonMode bool
	silent   bool
	file     *os.File
	mu       sync.Mutex
}

func NewWriter(jsonMode bool, silent bool, outputPath string) (*Writer, error) {
	w := &Writer{
		jsonMode: jsonMode,
		silent:   silent,
	}
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		w.file = f
	}
	return w, nil
}

func (w *Writer) Write(record *Record) {
	record.Timestamp = time.Now().UTC().Format(time.RFC3339)

	w.mu.Lock()
	defer w.mu.Unlock()

	var line string
	if w.jsonMode {
		data, _ := json.Marshal(record)
		line = string(data)
	} else {
		line = fmt.Sprintf("%s [%s] [%s]", record.Domain, record.Type, strings.Join(record.Answers, ", "))
	}

	fmt.Fprintln(os.Stdout, line)
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

func (w *Writer) Close() {
	if w.file != nil {
		w.file.Close()
	}
}
