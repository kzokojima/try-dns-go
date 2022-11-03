package dns

import (
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	now := time.Now().Unix()
	c := NewCache()
	if _, _, ok := c.Get("foo", now); ok {
		t.Fail()
	}
	c.Set("foo", "bar", now)
	if _, _, ok := c.Get("foo", now); ok {
		t.Error("get")
	}
	c.Set("foo", "bar", now+600)
	val, ttl, ok := c.Get("foo", now)
	if val != "bar" || ttl != 600 || !ok {
		t.Error("get")
	}
}
