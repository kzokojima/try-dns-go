package dns

import (
	"sync"
)

type Cache struct {
	store sync.Map
}

type CacheEntry struct {
	expires int64
	value   any
}

func NewCache() *Cache {
	return &Cache{
		sync.Map{},
	}
}

func (c *Cache) Get(key any, now int64) (value any, ttl int64, ok bool) {
	s := &c.store
	v, ok := s.Load(key)
	if ok {
		if now < v.(CacheEntry).expires {
			value = v.(CacheEntry).value
			ttl = v.(CacheEntry).expires - now
		} else {
			s.Delete(key)
			ok = false
		}
	}
	return
}

func (c *Cache) Set(key any, value any, expires int64) {
	s := &c.store
	s.Store(key, CacheEntry{expires, value})
}
