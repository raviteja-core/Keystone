package io.github.ravitejacore.keystone.client;

import io.github.ravitejacore.keystone.client.model.BatchCheckRequest;
import io.github.ravitejacore.keystone.client.model.BatchCheckResponse;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.Consistency;
import io.github.ravitejacore.keystone.client.model.ExpandRequest;
import io.github.ravitejacore.keystone.client.model.ExpandResponse;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsResponse;
import io.github.ravitejacore.keystone.client.model.ResourceRef;
import io.github.ravitejacore.keystone.client.model.SubjectRef;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsResponse;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

/**
 * High-assurance client interface for Keystone ReBAC Authz Engine.
 */
public interface PermissionClient {

    /**
     * Evaluates whether a subject is granted a permission on a resource.
     */
    CheckResponse check(CheckRequest request);

    /**
     * Convenience method to check a single permission.
     */
    default boolean check(ResourceRef resource, String permission, SubjectRef subject) {
        return check(CheckRequest.of(resource, permission, subject)).allowed();
    }

    /**
     * Convenience method to check a single permission with explicit consistency.
     */
    default boolean check(ResourceRef resource, String permission, SubjectRef subject, Consistency consistency) {
        return check(CheckRequest.of(resource, permission, subject, consistency)).allowed();
    }

    /**
     * Evaluates a batch of permission checks in a single round-trip.
     */
    BatchCheckResponse batchCheck(BatchCheckRequest request);

    /**
     * Writes or deletes relationship tuples in the Authz engine.
     */
    WriteRelationshipsResponse write(WriteRelationshipsRequest request);

    /**
     * Reads existing relationship tuples matching criteria.
     */
    ReadRelationshipsResponse read(ReadRelationshipsRequest request);

    /**
     * Expands the userset tree for an object and permission.
     */
    ExpandResponse expand(ExpandRequest request);

    /**
     * Returns the latest consistency Zookie observed by this client.
     */
    String getLatestZookie();

    /**
     * Manually updates the client's latest consistency Zookie.
     */
    void setLatestZookie(String zookie);

    static Builder builder() {
        return new Builder();
    }

    class Builder {
        private URI baseUrl;
        private TokenProvider tokenProvider;
        private HttpClient httpClient;
        private Duration timeout = Duration.ofSeconds(5);
        private Consistency defaultConsistency;

        public Builder baseUrl(URI uri) {
            this.baseUrl = uri;
            return this;
        }

        public Builder baseUrl(String url) {
            this.baseUrl = URI.create(url);
            return this;
        }

        public Builder tokenProvider(TokenProvider tokenProvider) {
            this.tokenProvider = tokenProvider;
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder defaultConsistency(Consistency consistency) {
            this.defaultConsistency = consistency;
            return this;
        }

        public PermissionClient build() {
            return new KeystonePermissionClient(baseUrl, tokenProvider, httpClient, timeout, defaultConsistency);
        }
    }
}
