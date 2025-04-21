// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/awslabs/ar-go-tools/internal/formatutil"
)

// LogLevel represents a logging level
type LogLevel int

const (
	// ErrLevel =1 - the minimum level of logging.
	ErrLevel LogLevel = iota + 1

	// WarnLevel =2 - the level for logging warnings, and errors
	WarnLevel

	// InfoLevel =3 - the level for logging high-level information, results
	InfoLevel

	// DebugLevel =4 - the level for debugging information. The tool will run properly on large programs with
	// that level of debug information.
	DebugLevel

	// TraceLevel =5 - the level for tracing. The tool will not run properly on large programs with that level
	// of information, but this is useful on smaller testing programs.
	TraceLevel
)

const contextSepChar = "."

// LogGroup holds a set of loggers that will be called depending on the logging kind
type LogGroup struct {
	Level        LogLevel
	suppressWarn bool
	contexts     []string
	trace        *log.Logger
	debug        *log.Logger
	info         *log.Logger
	warn         *log.Logger
	err          *log.Logger
}

// NewLogGroup returns a log group that is configured to the logging settings stored inside the config
func NewLogGroup(config *Config) *LogGroup {
	if config == nil {
		// Return a default config with nil arguments
		return &LogGroup{
			Level:        InfoLevel,
			suppressWarn: false,
			contexts:     []string{},
			trace:        log.New(os.Stdout, formatutil.Faint("[TRACE]")+" ", 0),
			debug:        log.New(os.Stdout, "[DEBUG]"+" ", 0),
			info:         log.New(os.Stdout, formatutil.Green("[INFO]")+" ", 0),
			warn:         log.New(os.Stdout, formatutil.Yellow("[WARN]")+" ", 0),
			err:          log.New(os.Stdout, formatutil.Red("[ERROR]")+" ", 0),
		}
	}
	l := &LogGroup{
		Level:        LogLevel(config.LogLevel),
		suppressWarn: config.SilenceWarn,
		contexts:     []string{},
		trace:        log.New(os.Stdout, formatutil.Faint("[TRACE]")+" ", 0),
		debug:        log.New(os.Stdout, "[DEBUG]"+" ", 0),
		info:         log.New(os.Stdout, formatutil.Green("[INFO]")+" ", 0),
		warn:         log.New(os.Stdout, formatutil.Yellow("[WARN]")+" ", 0),
		err:          log.New(os.Stdout, formatutil.Red("[ERROR]")+" ", 0),
	}
	return l
}

// PushContext pushes a context string on the prefix of the logger
func (l *LogGroup) PushContext(s string) {
	l.contexts = append(l.contexts, s)
	l.resetLoggingPostPrefix()
	l.setLoggingPostPrefix(strings.Join(l.contexts, formatutil.Faint(contextSepChar)))
}

// PopContext pops a context string off the prefix of the logger
func (l *LogGroup) PopContext() {
	if len(l.contexts) >= 1 {
		l.contexts = l.contexts[:len(l.contexts)-1]
	}
	l.resetLoggingPostPrefix()
	l.setLoggingPostPrefix(strings.Join(l.contexts, formatutil.Faint(contextSepChar)))
}

func formatTargetPrefix(target string) string {
	return formatutil.Faint(contextSepChar) + target + " "
}

func setPrefixToTarget(logger *log.Logger, target string) {
	prefix := logger.Prefix()
	logger.SetPrefix(strings.TrimSpace(prefix) + formatTargetPrefix(target))
}

func resetPrefix(logger *log.Logger) {
	logger.SetPrefix(strings.Split(logger.Prefix(), contextSepChar)[0] + " ")
}

func (l *LogGroup) setLoggingPostPrefix(target string) {
	l.resetLoggingPostPrefix()
	setPrefixToTarget(l.trace, target)
	setPrefixToTarget(l.debug, target)
	setPrefixToTarget(l.info, target)
	setPrefixToTarget(l.warn, target)
	setPrefixToTarget(l.err, target)
}

// resetLoggingPostPrefix removes the logging context (using the marker contextSepChar in the prefix)
func (l *LogGroup) resetLoggingPostPrefix() {
	resetPrefix(l.trace)
	resetPrefix(l.debug)
	resetPrefix(l.info)
	resetPrefix(l.warn)
	resetPrefix(l.err)

}

// SetAllOutput sets all the output writers to the writer provided
func (l *LogGroup) SetAllOutput(w io.Writer) {
	l.trace.SetOutput(w)
	l.debug.SetOutput(w)
	l.info.SetOutput(w)
	l.warn.SetOutput(w)
	l.err.SetOutput(w)
}

// SetAllFlags sets the flag of all loggers in the log group to the argument provided
func (l *LogGroup) SetAllFlags(x int) {
	l.trace.SetFlags(x)
	l.debug.SetFlags(x)
	l.info.SetFlags(x)
	l.warn.SetFlags(x)
	l.err.SetFlags(x)
}

// Tracef calls Trace.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Tracef(format string, v ...any) {
	if l.Level >= TraceLevel {
		l.trace.Printf(format, v...)
	}
}

// Debugf calls Debug.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Debugf(format string, v ...any) {
	if l.Level >= DebugLevel {
		l.debug.Printf(format, v...)
	}
}

// Infof calls Info.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Infof(format string, v ...any) {
	if l.Level >= InfoLevel {
		l.info.Printf(format, v...)
	}
}

// Warnf calls Warn.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Warnf(format string, v ...any) {
	if l.Level >= WarnLevel && !l.suppressWarn {
		l.warn.Printf(format, v...)
	}
}

// Errorf calls Error.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Errorf(format string, v ...any) {
	if l.Level >= ErrLevel {
		l.err.Printf(format, v...)
	}
}

// Trace calls Trace.Print to print to the trace logger. Arguments are handled in the manner of Print
func (l *LogGroup) Trace(msg string) {
	if l.Level >= TraceLevel {
		l.trace.Print(msg)
	}
}

// Debug calls Debug.Print to print to the trace logger. Arguments are handled in the manner of Print
func (l *LogGroup) Debug(msg string) {
	if l.Level >= DebugLevel {
		l.debug.Print(msg)
	}
}

// Info calls Info.Print to print to the trace logger. Arguments are handled in the manner of Print
func (l *LogGroup) Info(msg string) {
	if l.Level >= InfoLevel {
		l.info.Print(msg)
	}
}

// Warn calls Warn.Print to print to the trace logger. Arguments are handled in the manner of Print
func (l *LogGroup) Warn(msg string) {
	if l.Level >= WarnLevel && !l.suppressWarn {
		l.warn.Print(msg)
	}
}

// Error calls Error.Print to print to the trace logger. Arguments are handled in the manner of Print
func (l *LogGroup) Error(msg string) {
	if l.Level >= ErrLevel {
		l.err.Print(msg)
	}
}

// GetDebug returns the debug level logger, for applications that need a logger as input
func (l *LogGroup) GetDebug() *log.Logger {
	return l.debug
}

// GetError returns the error logger, for applications that need a logger as input
func (l *LogGroup) GetError() *log.Logger {
	return l.debug
}

// SetError sets the output writer of the error logger
func (l *LogGroup) SetError(w io.Writer) {
	l.err.SetOutput(w)
}

// LogsError returns true if the log group logs error messages. Note that this is the lowest logging level, and if
// this returns false, it implies that the log group does not log anything.
func (l *LogGroup) LogsError() bool {
	return l.Level >= ErrLevel
}

// LogsWarning returns true if the log group logs warning messages
func (l *LogGroup) LogsWarning() bool {
	return l.Level >= WarnLevel && !l.suppressWarn
}

// LogsInfo returns true if the log group logs info messages
func (l *LogGroup) LogsInfo() bool {
	return l.Level >= InfoLevel
}

// LogsDebug returns true if the log group logs debug messages
func (l *LogGroup) LogsDebug() bool {
	return l.Level >= DebugLevel
}

// LogsTrace returns true if the log group logs trace messages
func (l *LogGroup) LogsTrace() bool {
	return l.Level >= TraceLevel
}

// Infoboxf prints info-level logging in a box.
func (l *LogGroup) Infoboxf(format string, v ...any) {
	// Example:
	// ╭───────────────────────────────╮
	// │  this is the message to print │
	// ╰───────────────────────────────╯
	contents := fmt.Sprintf(format, v...)
	contentsLines := strings.Split(contents, "\n")
	n := 0
	for _, line := range contentsLines {
		n = max(n, len(line))
	}
	bar := strings.Repeat("─", n+2)
	l.Info("╭" + bar + "╮\n")
	for _, content := range contentsLines {
		l.Info("│ " + content + " │\n")
	}
	l.Info("╰" + bar + "╯\n")
}
