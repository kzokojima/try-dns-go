package dns

import (
	"fmt"
	"log"
)

type LogLevel byte

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

var LogLevelTexts = []string{
	"DEBUG",
	"INFO",
	"WARN",
	"ERROR",
}

func (lv LogLevel) String() string {
	return LogLevelTexts[lv]
}

type Logger struct {
	logLevel LogLevel
}

var Log = Logger{LogLevelInfo}

func (l *Logger) SetLogLevel(lv LogLevel) {
	l.logLevel = lv
}

func (l *Logger) Debug(v ...any) {
	l.output(LogLevelDebug, fmt.Sprint(v...))
}

func (l *Logger) Debugf(f string, v ...any) {
	l.output(LogLevelDebug, fmt.Sprintf(f, v...))
}

func (l *Logger) Info(v ...any) {
	l.output(LogLevelInfo, fmt.Sprint(v...))
}

func (l *Logger) Infof(f string, v ...any) {
	l.output(LogLevelInfo, fmt.Sprintf(f, v...))
}

func (l *Logger) Warn(v ...any) {
	l.output(LogLevelWarn, fmt.Sprint(v...))
}

func (l *Logger) Warnf(f string, v ...any) {
	l.output(LogLevelWarn, fmt.Sprintf(f, v...))
}

func (l *Logger) Error(v ...any) {
	l.output(LogLevelError, fmt.Sprint(v...))
}

func (l *Logger) Errorf(f string, v ...any) {
	l.output(LogLevelError, fmt.Sprintf(f, v...))
}

func (l *Logger) output(lv LogLevel, msg string) {
	if l.logLevel <= lv {
		log.Printf("[%s] %s", lv.String(), msg)
	}
}
