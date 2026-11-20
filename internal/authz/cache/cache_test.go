package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/raviteja-core/keystone/internal/authz/cache"
)

func TestMemoryCache_GetSetInvalidate(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	key := "tenant1:doc:123#view@user:alice"

	// 1. Initial miss
	allowed, found, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Errorf("expected not found")
	}

	// 2. Set allowed = true
	if err := c.Set(ctx, key, true, 50*time.Millisecond); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	// 3. Cache hit
	allowed, found, err = c.Get(ctx, key)
	if err != nil || !found || !allowed {
		t.Errorf("expected hit with allowed=true, got found=%v, allowed=%v, err=%v", found, allowed, err)
	}

	// 4. Invalidation
	if err := c.Invalidate(ctx, "tenant1:doc:123"); err != nil {
		t.Fatalf("invalidation failed: %v", err)
	}
	_, found, _ = c.Get(ctx, key)
	if found {
		t.Errorf("expected key to be invalidated")
	}
}
