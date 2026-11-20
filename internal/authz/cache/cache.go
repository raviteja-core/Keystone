package cache

import (
	"context"
	"sync"
	"time"
)

// Cache defines the permission check cache interface.
type Cache interface {
	// Get retrieves a cached check decision. Returns (allowed, found, error).
	Get(ctx context.Context, key string) (bool, bool, error)
	// Set stores a permission check decision with a TTL.
	Set(ctx context.Context, key string, allowed bool, ttl time.Duration) error
	// Invalidate evicts keys matching a prefix or pattern.
	Invalidate(ctx context.Context, prefix string) error
	// Close releases any allocated resources.
	Close() error
}

// MemoryCache is an in-memory thread-safe implementation of Cache.
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string]memoryItem
}

type memoryItem struct {
	allowed   bool
	expiresAt time.Time
}

// NewMemoryCache creates an in-memory check cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string]memoryItem),
	}
}

func (m *MemoryCache) Get(ctx context.Context, key string) (bool, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	item, exists := m.items[key]
	if !exists {
		return false, false, nil
	}
	if time.Now().After(item.expiresAt) {
		return false, false, nil
	}
	return item.allowed, true, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, allowed bool, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.items[key] = memoryItem{
		allowed:   allowed,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (m *MemoryCache) Invalidate(ctx context.Context, prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k := range m.items {
		if prefix == "" || len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(m.items, k)
		}
	}
	return nil
}

func (m *MemoryCache) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = nil
	return nil
}
