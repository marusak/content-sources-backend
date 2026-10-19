package parser

import (
	"fmt"
	"strings"
)

// FailureWarningLimit is how many ignored-entry warnings are included in the
// failure reason shown in the API. The full list stays in the downloadable log.
const FailureWarningLimit = 20

// Log is the human-readable trace of one parse.
type Log struct {
	lines []logLine
}

type logLine struct {
	warning bool
	text    string
}

func (l *Log) Printf(format string, args ...any) {
	if l == nil {
		return
	}
	l.lines = append(l.lines, logLine{text: fmt.Sprintf(format, args...)})
}

func (l *Log) Warningf(format string, args ...any) {
	if l == nil {
		return
	}
	l.lines = append(l.lines, logLine{warning: true, text: fmt.Sprintf(format, args...)})
}

func (l *Log) String() string {
	return l.format(false)
}

// Reason is the text returned when processing fails. Ignored-entry warnings are
// kept until FailureWarningLimit so the message stays readable in the UI.
func (l *Log) Reason() string {
	return l.format(true)
}

func (l *Log) format(capWarnings bool) string {
	if l == nil {
		return ""
	}
	var warnings []string
	var b strings.Builder
	for _, line := range l.lines {
		if line.warning {
			warnings = append(warnings, line.text)
			if capWarnings {
				continue
			}
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		if line.warning {
			b.WriteString("WARNING: ")
		}
		b.WriteString(line.text)
	}
	if !capWarnings || len(warnings) == 0 {
		return b.String()
	}
	shown := warnings
	extra := 0
	if len(warnings) > FailureWarningLimit {
		shown = warnings[:FailureWarningLimit]
		extra = len(warnings) - FailureWarningLimit
	}
	for _, text := range shown {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("WARNING: ")
		b.WriteString(text)
	}
	if extra > 0 {
		fmt.Fprintf(&b, "\n... and %d more ignored entries", extra)
	}
	return b.String()
}

func (l *Log) WarningCount() int {
	if l == nil {
		return 0
	}
	n := 0
	for _, line := range l.lines {
		if line.warning {
			n++
		}
	}
	return n
}

func (l *Log) fail(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if !strings.Contains(l.String(), msg) {
		l.Printf("%s", msg)
	}
	return &ReasonError{
		Reason:    l.Reason(),
		Full:      l.String(),
		Truncated: l.WarningCount() > FailureWarningLimit,
		Err:       err,
	}
}

// ReasonError is a manifest failure whose Error text is safe to show to the user.
type ReasonError struct {
	Reason    string
	Full      string
	Truncated bool
	Err       error
}

func (e *ReasonError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "could not parse manifest"
}

func (e *ReasonError) Unwrap() error { return e.Err }

// Download is the full parser log when the shown reason omitted ignored entries.
func (e *ReasonError) Download() string {
	if e == nil || !e.Truncated || e.Full == "" {
		return ""
	}
	return e.Full
}

// trace collects skipped-entry warnings so they can be written after summary lines.
type trace struct {
	log     *Log
	skipped int
	pending []string
}

func newTrace() *trace {
	return &trace{log: &Log{}}
}

func (t *trace) note(format string, args ...any) {
	if t == nil {
		return
	}
	t.log.Printf(format, args...)
}

func (t *trace) skip(format string, args ...any) {
	if t == nil {
		return
	}
	t.skipped++
	t.pending = append(t.pending, fmt.Sprintf(format, args...))
}

func (t *trace) flush() {
	if t == nil {
		return
	}
	for _, msg := range t.pending {
		t.log.Warningf("%s", msg)
	}
	t.pending = t.pending[:0]
}
