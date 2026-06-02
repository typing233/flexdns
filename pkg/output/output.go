package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type CDNInfo struct {
	Provider string `json:"provider"`
	Matched  string `json:"matched,omitempty"`
}

type ASNInfo struct {
	ASN  string `json:"asn"`
	Desc string `json:"desc,omitempty"`
}

type Record struct {
	Domain     string   `json:"domain"`
	Type       string   `json:"type"`
	Resolver   string   `json:"resolver"`
	Protocol   string   `json:"protocol"`
	Answers    []string `json:"answers,omitempty"`
	Rcode      string   `json:"rcode,omitempty"`
	CDN        *CDNInfo `json:"cdn,omitempty"`
	ASN        *ASNInfo `json:"asn,omitempty"`
	Authority  []string `json:"authority,omitempty"`
	Additional []string `json:"additional,omitempty"`
	Timestamp  string   `json:"timestamp"`
}

type CompactRecord struct {
	Domain  string   `json:"d"`
	Type    string   `json:"t"`
	Answers []string `json:"a"`
	CDN     string   `json:"cdn,omitempty"`
	ASN     string   `json:"asn,omitempty"`
}

type WriterOptions struct {
	JSONMode    bool
	CompactJSON bool
	Silent      bool
	OutputPath  string
	ShowAnswer  bool
}

type Writer struct {
	jsonMode    bool
	compactJSON bool
	silent      bool
	showAnswer  bool
	file        *os.File
	mu          sync.Mutex
}

func NewWriter(wopts WriterOptions) (*Writer, error) {
	w := &Writer{
		jsonMode:    wopts.JSONMode,
		compactJSON: wopts.CompactJSON,
		silent:      wopts.Silent,
		showAnswer:  wopts.ShowAnswer,
	}
	if wopts.OutputPath != "" {
		f, err := os.Create(wopts.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		w.file = f
	}
	return w, nil
}

func (w *Writer) Write(record *Record) {
	record.Timestamp = time.Now().UTC().Format(time.RFC3339)

	if !w.showAnswer {
		record.Answers = nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var line string
	if w.jsonMode {
		if w.compactJSON {
			compact := CompactRecord{
				Domain:  record.Domain,
				Type:    record.Type,
				Answers: record.Answers,
			}
			if record.CDN != nil {
				compact.CDN = record.CDN.Provider
			}
			if record.ASN != nil {
				compact.ASN = record.ASN.ASN
			}
			data, _ := json.Marshal(compact)
			line = string(data)
		} else {
			data, _ := json.Marshal(record)
			line = string(data)
		}
	} else {
		var parts []string
		parts = append(parts, record.Domain)
		parts = append(parts, fmt.Sprintf("[%s]", record.Type))
		if len(record.Answers) > 0 {
			parts = append(parts, fmt.Sprintf("[%s]", strings.Join(record.Answers, ", ")))
		}
		if record.CDN != nil {
			parts = append(parts, fmt.Sprintf("[CDN: %s]", record.CDN.Provider))
		}
		if record.ASN != nil {
			parts = append(parts, fmt.Sprintf("[%s %s]", record.ASN.ASN, record.ASN.Desc))
		}
		if len(record.Authority) > 0 {
			parts = append(parts, fmt.Sprintf("[Authority: %s]", strings.Join(record.Authority, "; ")))
		}
		if len(record.Additional) > 0 {
			parts = append(parts, fmt.Sprintf("[Additional: %s]", strings.Join(record.Additional, "; ")))
		}
		line = strings.Join(parts, " ")
	}

	fmt.Fprintln(os.Stdout, line)
	if w.file != nil {
		fmt.Fprintln(w.file, line)
	}
}

func (w *Writer) WriteRaw(line string) {
	w.mu.Lock()
	defer w.mu.Unlock()
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
