package dns

import (
	"log"
	"strings"
	"testing"
)

func TestLog(t *testing.T) {
	var s string

	// backup
	w := log.Writer()
	defer log.SetOutput(w)

	// change log output
	buf := &strings.Builder{}
	log.SetOutput(buf)

	// no output
	Log.Debug("foo")
	s = buf.String()
	if s != "" {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Debugf("%v", "foo")
	s = buf.String()
	if s != "" {
		t.Errorf("actual: %v(%v)", s, len(s))
	}

	// change log level
	Log.SetLogLevel(LogLevelDebug)
	defer Log.SetLogLevel(LogLevelInfo)

	// log has output
	Log.Debug("foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[DEBUG] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Debugf("%v", "foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[DEBUG] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Info("foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[INFO] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Infof("%v", "foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[INFO] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Warn("foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[WARN] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Warnf("%v", "foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[WARN] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Error("foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[ERROR] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
	Log.Errorf("%v", "foo")
	s = buf.String()
	if !strings.HasSuffix(s, "[ERROR] foo\n") {
		t.Errorf("actual: %v(%v)", s, len(s))
	}
}
