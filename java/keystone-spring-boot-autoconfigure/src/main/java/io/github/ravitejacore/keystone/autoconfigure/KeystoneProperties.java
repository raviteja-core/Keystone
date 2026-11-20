package io.github.ravitejacore.keystone.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;

/**
 * Configuration properties for Keystone IAM and ReBAC client.
 */
@ConfigurationProperties(prefix = "keystone")
public class KeystoneProperties {

    /**
     * Whether Keystone integration is enabled. Default true.
     */
    private boolean enabled = true;

    /**
     * OIDC Issuer URI of the Keystone Auth Server (e.g. http://localhost:8080).
     */
    private URI issuerUri;

    /**
     * Expected audience for access tokens issued to this service.
     */
    private String audience;

    /**
     * Default subject type for authenticated users (default "user").
     */
    private String subjectType = "user";

    /**
     * Authz Engine configuration.
     */
    private AuthzProperties authz = new AuthzProperties();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public URI getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(URI issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public AuthzProperties getAuthz() {
        return authz;
    }

    public void setAuthz(AuthzProperties authz) {
        this.authz = authz;
    }

    public static class AuthzProperties {
        /**
         * Base URL of the Keystone Authz Engine (e.g. http://localhost:8081).
         */
        private URI url;

        /**
         * Client ID for machine-to-machine authentication against the Authz Engine.
         */
        private String clientId;

        /**
         * Client Secret for machine-to-machine authentication against the Authz Engine.
         */
        private String clientSecret;

        /**
         * OAuth2 scope for M2M token request (default "authz:check authz:write").
         */
        private String scope = "authz:check authz:write";

        /**
         * HTTP timeout for Authz Engine calls (default 500ms).
         */
        private Duration timeout = Duration.ofMillis(500);

        /**
         * Failure mode when the engine cannot be reached. Only "closed" is supported.
         */
        private String failMode = "closed";

        /**
         * In-process caching configuration for permission checks.
         */
        private CacheProperties cache = new CacheProperties();

        public URI getUrl() {
            return url;
        }

        public void setUrl(URI url) {
            this.url = url;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public Duration getTimeout() {
            return timeout;
        }

        public void setTimeout(Duration timeout) {
            this.timeout = timeout;
        }

        public String getFailMode() {
            return failMode;
        }

        public void setFailMode(String failMode) {
            this.failMode = failMode;
        }

        public CacheProperties getCache() {
            return cache;
        }

        public void setCache(CacheProperties cache) {
            this.cache = cache;
        }
    }

    public static class CacheProperties {
        private boolean enabled = true;
        private Duration ttl = Duration.ofSeconds(5);
        private long maxSize = 10000;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Duration getTtl() {
            return ttl;
        }

        public void setTtl(Duration ttl) {
            this.ttl = ttl;
        }

        public long getMaxSize() {
            return maxSize;
        }

        public void setMaxSize(long maxSize) {
            this.maxSize = maxSize;
        }
    }
}
