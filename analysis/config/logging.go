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
	"io"
	"log"
)

type LogLevel int

const (
	// ErrLevel=1 - the minimum level of logging.
	ErrLevel LogLevel = iota + 1

	// WarnLEvel=2 - the level for logging warnings, and errors
	WarnLevel

	// InfoLevel=3 - the level for logging high-level information, results
	InfoLevel

	// DebugLevel=4 - the level for debugging information. The tool will run properly on large programs with
	// that level of debug information.
	DebugLevel

	// TraceLevel=5 - the level for tracing. The tool will not run properly on large programs with that level
	// of information, but this is useful on smaller testing programs.
	TraceLevel
)

type LogGroup struct {
	Level LogLevel
	trace *log.Logger
	debug *log.Logger
	info  *log.Logger
	warn  *log.Logger
	err   *log.Logger
}

// NewLogGroup returns a log group that is configured to the logging settings stored inside the config
func NewLogGroup(config *Config) *LogGroup {
	l := &LogGroup{
		Level: LogLevel(config.LogLevel),
		trace: log.Default(),
		debug: log.Default(),
		info:  log.Default(),
		warn:  log.Default(),
		err:   log.Default(),
	}

	l.trace.SetPrefix("[TRACE] ")
	l.debug.SetPrefix("[DEBUG] ")
	l.info.SetPrefix("[INFO] ")
	l.warn.SetPrefix("[WARN] ")
	l.err.SetPrefix("[ERROR] ")
	return l
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
	if l.Level >= WarnLevel {
		l.warn.Printf(format, v...)
	}
}

// Errorf calls Error.Printf to print to the trace logger. Arguments are handled in the manner of Printf
func (l *LogGroup) Errorf(format string, v ...any) {
	if l.Level >= ErrLevel {
		l.err.Printf(format, v...)
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

// LogsErrors returns true if the log group logs error messages. Note that this is the lowest logging level, and if
// this returns false, it implies that the log group does not log anything.
func (l *LogGroup) LogsError() bool {
	return l.Level >= ErrLevel
}

// LogsWarning returns true if the log group logs warning messages
func (l *LogGroup) LogsWarning() bool {
	return l.Level >= WarnLevel
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
