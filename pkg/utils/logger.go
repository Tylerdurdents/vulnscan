package utils

import (
	"fmt"
	"os"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	FATAL
)

// Logger provides structured logging functionality
type Logger struct {
	level  LogLevel
	prefix string
}

// NewLogger creates a new logger with the specified level
func NewLogger(level LogLevel, prefix string) *Logger {
	return &Logger{
		level:  level,
		prefix: prefix,
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

// log outputs a log message if the level is sufficient
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	levelStr := ""
	switch level {
	case DEBUG:
		levelStr = "DEBUG"
	case INFO:
		levelStr = "INFO"
	case WARNING:
		levelStr = "WARNING"
	case ERROR:
		levelStr = "ERROR"
	case FATAL:
		levelStr = "FATAL"
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)

	if l.prefix != "" {
		fmt.Fprintf(os.Stderr, "[%s] [%s] %s: %s\n", timestamp, levelStr, l.prefix, message)
	} else {
		fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", timestamp, levelStr, message)
	}
}
