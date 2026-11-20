package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCache provides a distributed Redis-backed cache for Zanzibar checks.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache creates a new RedisCache client.
func NewRedisCache(redisURL string) (*RedisCache, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url: %w", err)
	}

	client := redis.NewClient(opts)
	return &RedisCache{client: client}, nil
}

// NewRedisCacheFromClient wraps an existing redis.Client.
func NewRedisCacheFromClient(client *redis.Client) *RedisCache {
	return &RedisCache{client: client}
}

func (r *RedisCache) Get(ctx context.Context, key string) (bool, bool, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, false, nil
		}
		return false, false, err
	}
	return val == "1" || val == "true", true, nil
}

func (r *RedisCache) Set(ctx context.Context, key string, allowed bool, ttl time.Duration) error {
	val := "0"
	if allowed {
		val = "1"
	}
	return r.client.Set(ctx, key, val, ttl).Err()
}

func (r *RedisCache) Invalidate(ctx context.Context, prefix string) error {
	iter := r.client.Scan(ctx, 0, prefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		_ = r.client.Del(ctx, iter.Val()).Err()
	}
	return iter.Err()
}

func (r *RedisCache) Close() error {
	return r.client.Close()
}
