package io.github.ravitejacore.keystone.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ravitejacore.keystone.client.model.BatchCheckRequest;
import io.github.ravitejacore.keystone.client.model.BatchCheckResponse;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.Consistency;
import io.github.ravitejacore.keystone.client.model.ExpandRequest;
import io.github.ravitejacore.keystone.client.model.ExpandResponse;
import io.github.ravitejacore.keystone.client.model.ProblemDetails;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsResponse;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Concrete implementation of PermissionClient communicating with Keystone ReBAC Authz Engine over HTTP.
 * Fail-closed design: timeouts and communication errors throw KeystoneServiceUnavailableException.
 */
public class KeystonePermissionClient implements PermissionClient {
    private final URI baseUrl;
    private final TokenProvider tokenProvider;
    private final HttpClient httpClient;
    private final Duration timeout;
    private final Consistency defaultConsistency;
    private final ObjectMapper objectMapper;
    private final AtomicReference<String> latestZookie = new AtomicReference<>();

    public KeystonePermissionClient(URI baseUrl, TokenProvider tokenProvider, HttpClient httpClient, Duration timeout, Consistency defaultConsistency) {
        this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
        this.tokenProvider = tokenProvider;
        this.httpClient = httpClient != null ? httpClient : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        this.timeout = timeout != null ? timeout : Duration.ofSeconds(5);
        this.defaultConsistency = defaultConsistency;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public CheckResponse check(CheckRequest request) {
        Objects.requireNonNull(request, "request must not be null");

        // Apply automatic consistency if not specified
        CheckRequest effectiveReq = request;
        if (effectiveReq.consistency() == null) {
            String currentZookie = latestZookie.get();
            if (currentZookie != null && !currentZookie.isBlank()) {
                effectiveReq = new CheckRequest(
                    effectiveReq.object(),
                    effectiveReq.permission(),
                    effectiveReq.subject(),
                    Consistency.atLeastAsFresh(currentZookie)
                );
            } else if (defaultConsistency != null) {
                effectiveReq = new CheckRequest(
                    effectiveReq.object(),
                    effectiveReq.permission(),
                    effectiveReq.subject(),
                    defaultConsistency
                );
            }
        }

        return executePost("/v1/check", effectiveReq, CheckResponse.class);
    }

    @Override
    public BatchCheckResponse batchCheck(BatchCheckRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        return executePost("/v1/check/batch", request, BatchCheckResponse.class);
    }

    @Override
    public WriteRelationshipsResponse write(WriteRelationshipsRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        WriteRelationshipsResponse response = executePost("/v1/relationships/write", request, WriteRelationshipsResponse.class);
        if (response.zookie() != null && !response.zookie().isBlank()) {
            setLatestZookie(response.zookie());
        }
        return response;
    }

    @Override
    public ReadRelationshipsResponse read(ReadRelationshipsRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        return executePost("/v1/relationships/read", request, ReadRelationshipsResponse.class);
    }

    @Override
    public ExpandResponse expand(ExpandRequest request) {
        Objects.requireNonNull(request, "request must not be null");
        return executePost("/v1/expand", request, ExpandResponse.class);
    }

    @Override
    public String getLatestZookie() {
        return latestZookie.get();
    }

    @Override
    public void setLatestZookie(String zookie) {
        if (zookie != null && !zookie.isBlank()) {
            latestZookie.set(zookie);
        }
    }

    private <T> T executePost(String path, Object payload, Class<T> responseClass) {
        URI endpoint = resolveEndpoint(path);

        try {
            byte[] bodyBytes = objectMapper.writeValueAsBytes(payload);

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, application/problem+json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes));

            if (tokenProvider != null) {
                String token = tokenProvider.getToken();
                if (token != null && !token.isBlank()) {
                    reqBuilder.header("Authorization", "Bearer " + token);
                }
            }

            HttpResponse<byte[]> response = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());

            // Track Zookie from response header if present
            Optional<String> headerZookie = response.headers().firstValue("X-Keystone-Zookie");
            headerZookie.ifPresent(this::setLatestZookie);

            if (response.statusCode() >= 400) {
                handleErrorResponse(response);
            }

            return objectMapper.readValue(response.body(), responseClass);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new KeystoneServiceUnavailableException("Authz engine communication failed for " + endpoint + ": " + e.getMessage(), e);
        }
    }

    private void handleErrorResponse(HttpResponse<byte[]> response) {
        byte[] body = response.body();
        if (body != null && body.length > 0) {
            try {
                ProblemDetails problem = objectMapper.readValue(body, ProblemDetails.class);
                if (problem.title() != null) {
                    throw new KeystoneProblemException(problem);
                }
            } catch (KeystoneProblemException e) {
                throw e;
            } catch (Exception ignored) {
                // Not standard ProblemDetails JSON, fall back below
            }
            String rawBody = new String(body);
            throw new KeystoneException("Authz engine returned HTTP " + response.statusCode() + ": " + rawBody);
        }
        throw new KeystoneException("Authz engine returned HTTP " + response.statusCode());
    }

    private URI resolveEndpoint(String path) {
        String base = baseUrl.toString();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        String cleanPath = path.startsWith("/") ? path : "/" + path;
        return URI.create(base + cleanPath);
    }
}
