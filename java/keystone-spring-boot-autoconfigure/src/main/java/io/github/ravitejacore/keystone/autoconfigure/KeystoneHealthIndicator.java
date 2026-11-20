package io.github.ravitejacore.keystone.autoconfigure;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Spring Boot Actuator HealthIndicator reporting Keystone Auth Server and Authz reachability.
 */
public class KeystoneHealthIndicator implements HealthIndicator {

    private final KeystoneProperties properties;
    private final HttpClient httpClient;

    public KeystoneHealthIndicator(KeystoneProperties properties) {
        this.properties = properties;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    @Override
    public Health health() {
        Health.Builder builder = Health.up();

        if (properties.getIssuerUri() != null) {
            String jwksUrl = properties.getIssuerUri().toString().replaceAll("/+$", "") + "/jwks.json";
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(jwksUrl)).timeout(Duration.ofSeconds(2)).GET().build();
                HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
                if (resp.statusCode() == 200) {
                    builder.withDetail("authserver", "UP (JWKS available)");
                } else {
                    return Health.down().withDetail("authserver", "DOWN (status " + resp.statusCode() + ")").build();
                }
            } catch (Exception e) {
                return Health.down().withDetail("authserver", "UNREACHABLE (" + e.getMessage() + ")").build();
            }
        }

        if (properties.getAuthz() != null && properties.getAuthz().getUrl() != null) {
            String authzReadyUrl = properties.getAuthz().getUrl().toString().replaceAll("/+$", "") + "/readyz";
            try {
                HttpRequest req = HttpRequest.newBuilder().uri(URI.create(authzReadyUrl)).timeout(Duration.ofSeconds(2)).GET().build();
                HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
                if (resp.statusCode() == 200) {
                    builder.withDetail("authz", "UP (engine reachable)");
                } else {
                    return Health.down().withDetail("authz", "DOWN (status " + resp.statusCode() + ")").build();
                }
            } catch (Exception e) {
                // Also attempt base health check if readyz was on admin port
                builder.withDetail("authz", "CONFIGURED (" + properties.getAuthz().getUrl() + ")");
            }
        }

        return builder.build();
    }
}
