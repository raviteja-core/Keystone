package io.github.ravitejacore.keystone.autoconfigure;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.ravitejacore.keystone.client.PermissionClient;
import io.github.ravitejacore.keystone.client.model.BatchCheckRequest;
import io.github.ravitejacore.keystone.client.model.BatchCheckResponse;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.Consistency;
import io.github.ravitejacore.keystone.client.model.ExpandRequest;
import io.github.ravitejacore.keystone.client.model.ExpandResponse;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsResponse;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsResponse;

import java.time.Duration;
import java.util.Objects;

/**
 * Decorator adding in-memory Caffeine caching to PermissionClient check queries.
 * Cache entries are keyed by subject, resource, permission, and snapshot consistency token.
 */
public class CachedPermissionClient implements PermissionClient {

    private final PermissionClient delegate;
    private final Cache<CheckCacheKey, CheckResponse> checkCache;

    public record CheckCacheKey(
        String subjectType,
        String subjectId,
        String objectType,
        String objectId,
        String permission,
        String consistencyMode,
        String consistencyToken
    ) {
    }

    public CachedPermissionClient(PermissionClient delegate, Duration ttl, long maxSize) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.checkCache = Caffeine.newBuilder()
            .expireAfterWrite(ttl)
            .maximumSize(maxSize)
            .build();
    }

    @Override
    public CheckResponse check(CheckRequest request) {
        // FULLY_CONSISTENT checks MUST bypass cache to guarantee strict consistency
        if (request.consistency() != null && Consistency.FULLY_CONSISTENT.equals(request.consistency().mode())) {
            return delegate.check(request);
        }

        String mode = request.consistency() != null && request.consistency().mode() != null 
            ? request.consistency().mode() 
            : Consistency.AT_LEAST_AS_FRESH;
        String token = request.consistency() != null && request.consistency().token() != null 
            ? request.consistency().token() 
            : (delegate.getLatestZookie() != null ? delegate.getLatestZookie() : "");

        CheckCacheKey key = new CheckCacheKey(
            request.subject().type(),
            request.subject().id(),
            request.object().type(),
            request.object().id(),
            request.permission(),
            mode,
            token
        );

        return checkCache.get(key, k -> delegate.check(request));
    }

    @Override
    public BatchCheckResponse batchCheck(BatchCheckRequest request) {
        return delegate.batchCheck(request);
    }

    @Override
    public WriteRelationshipsResponse write(WriteRelationshipsRequest request) {
        WriteRelationshipsResponse response = delegate.write(request);
        // Invalidate cached decisions on local write to maintain read-your-writes guarantees
        checkCache.invalidateAll();
        return response;
    }

    @Override
    public ReadRelationshipsResponse read(ReadRelationshipsRequest request) {
        return delegate.read(request);
    }

    @Override
    public ExpandResponse expand(ExpandRequest request) {
        return delegate.expand(request);
    }

    @Override
    public String getLatestZookie() {
        return delegate.getLatestZookie();
    }

    @Override
    public void setLatestZookie(String zookie) {
        delegate.setLatestZookie(zookie);
    }
}
