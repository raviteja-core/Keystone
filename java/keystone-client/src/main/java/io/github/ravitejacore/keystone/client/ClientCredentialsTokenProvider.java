package io.github.ravitejacore.keystone.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * TokenProvider implementing OAuth 2.0 client_credentials grant with safe in-memory caching.
 * Refreshes tokens proactively when within 30 seconds of expiry.
 */
public class ClientCredentialsTokenProvider implements TokenProvider {
    private final URI tokenUri;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ReentrantLock lock = new ReentrantLock();

    private volatile String cachedToken;
    private volatile Instant expiresAt = Instant.MIN;

    public ClientCredentialsTokenProvider(URI tokenUri, String clientId, String clientSecret, String scope, HttpClient httpClient, ObjectMapper objectMapper) {
        this.tokenUri = Objects.requireNonNull(tokenUri, "tokenUri must not be null");
        this.clientId = Objects.requireNonNull(clientId, "clientId must not be null");
        this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret must not be null");
        this.scope = scope;
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String getToken() throws KeystoneAuthenticationException {
        // Fast path: if token is cached and not within 30s of expiration, return it
        if (cachedToken != null && Instant.now().plusSeconds(30).isBefore(expiresAt)) {
            return cachedToken;
        }

        lock.lock();
        try {
            // Re-check condition under lock
            if (cachedToken != null && Instant.now().plusSeconds(30).isBefore(expiresAt)) {
                return cachedToken;
            }

            StringBuilder form = new StringBuilder();
            form.append("grant_type=").append(URLEncoder.encode("client_credentials", StandardCharsets.UTF_8));
            form.append("&client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
            form.append("&client_secret=").append(URLEncoder.encode(clientSecret, StandardCharsets.UTF_8));
            if (scope != null && !scope.isBlank()) {
                form.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
            }

            HttpRequest request = HttpRequest.newBuilder()
                .uri(tokenUri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new KeystoneAuthenticationException(
                    String.format("Token request to %s failed with HTTP %d: %s", tokenUri, response.statusCode(), response.body())
                );
            }

            JsonNode root = objectMapper.readTree(response.body());
            JsonNode accessTokenNode = root.get("access_token");
            if (accessTokenNode == null || accessTokenNode.asText().isBlank()) {
                throw new KeystoneAuthenticationException("Token response missing access_token claim: " + response.body());
            }

            long expiresInSeconds = root.has("expires_in") ? root.get("expires_in").asLong() : 600;
            this.cachedToken = accessTokenNode.asText();
            this.expiresAt = Instant.now().plusSeconds(expiresInSeconds);

            return cachedToken;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new KeystoneAuthenticationException("Failed to obtain M2M client_credentials token: " + e.getMessage(), e);
        } finally {
            lock.unlock();
        }
    }

    public static class Builder {
        private URI tokenUri;
        private String clientId;
        private String clientSecret;
        private String scope;
        private HttpClient httpClient;
        private ObjectMapper objectMapper;

        public Builder tokenUri(URI uri) {
            this.tokenUri = uri;
            return this;
        }

        public Builder tokenUri(String uri) {
            this.tokenUri = URI.create(uri);
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder objectMapper(ObjectMapper objectMapper) {
            this.objectMapper = objectMapper;
            return this;
        }

        public ClientCredentialsTokenProvider build() {
            return new ClientCredentialsTokenProvider(tokenUri, clientId, clientSecret, scope, httpClient, objectMapper);
        }
    }
}
