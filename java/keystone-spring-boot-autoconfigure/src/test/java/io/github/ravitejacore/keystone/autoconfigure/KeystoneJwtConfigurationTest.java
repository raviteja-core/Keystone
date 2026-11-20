package io.github.ravitejacore.keystone.autoconfigure;

import io.github.ravitejacore.keystone.autoconfigure.security.KeystoneJwtConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeystoneJwtConfigurationTest {

    private final KeystoneJwtConfiguration.JwtTokenTypeValidator validator =
        new KeystoneJwtConfiguration.JwtTokenTypeValidator();

    @Test
    @DisplayName("typ=at+jwt header passes validation")
    void validAtJwtHeaderPasses() {
        Jwt jwt = createJwtWithHeaders(Map.of("alg", "RS256", "typ", "at+jwt"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("typ=at+jwt case-insensitivity passes validation")
    void caseInsensitiveTypPasses() {
        Jwt jwt = createJwtWithHeaders(Map.of("alg", "RS256", "typ", "AT+JWT"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("typ=JWT (OIDC ID Token) fails validation per RFC 9068")
    void idTokenTypeFails() {
        Jwt jwt = createJwtWithHeaders(Map.of("alg", "RS256", "typ", "JWT"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).anyMatch(err -> err.getDescription().contains("expected 'at+jwt'"));
    }

    @Test
    @DisplayName("Missing typ header fails validation")
    void missingTypHeaderFails() {
        Jwt jwt = createJwtWithHeaders(Map.of("alg", "RS256"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertThat(result.hasErrors()).isTrue();
    }

    private Jwt createJwtWithHeaders(Map<String, Object> headers) {
        return new Jwt(
            "mock.jwt.token",
            Instant.now(),
            Instant.now().plusSeconds(3600),
            headers,
            Map.of("sub", "alice", "iss", "http://localhost:8080")
        );
    }
}
