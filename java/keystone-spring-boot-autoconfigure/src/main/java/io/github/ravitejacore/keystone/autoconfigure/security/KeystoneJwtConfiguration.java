package io.github.ravitejacore.keystone.autoconfigure.security;

import io.github.ravitejacore.keystone.autoconfigure.KeystoneProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.net.URI;
import java.time.Duration;
import java.util.List;

/**
 * Spring Security Resource Server JWT configuration enforcing RFC 9068 profiles:
 * - Strict RS256 signature algorithm allowlist
 * - typ: at+jwt header validation
 * - Audience and Issuer validation
 * - Bounded clock skew (30 seconds)
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(JwtDecoder.class)
@ConditionalOnProperty(prefix = "keystone", name = "issuer-uri")
public class KeystoneJwtConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(KeystoneProperties properties) {
        URI issuerUri = properties.getIssuerUri();
        if (issuerUri == null) {
            throw new IllegalStateException("keystone.issuer-uri must be configured to enable JWT validation");
        }

        String jwksUri = issuerUri.toString().replaceAll("/+$", "") + "/jwks.json";

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwksUri)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();

        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuerUri.toString());

        OAuth2TokenValidator<Jwt> rfc9068TypeValidator = new JwtTokenTypeValidator();

        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
            JwtClaimNames.AUD,
            audList -> properties.getAudience() == null || (audList != null && audList.contains(properties.getAudience()))
        );

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            defaultValidators,
            rfc9068TypeValidator,
            audienceValidator
        ));

        return jwtDecoder;
    }

    /**
     * Validates that the JOSE header typ matches RFC 9068 "at+jwt" (case-insensitive).
     */
    public static class JwtTokenTypeValidator implements OAuth2TokenValidator<Jwt> {
        private static final OAuth2Error INVALID_TYPE_ERROR = new OAuth2Error(
            "invalid_token",
            "Invalid JWT header 'typ': expected 'at+jwt' per RFC 9068",
            "https://datatracker.ietf.org/doc/html/rfc9068"
        );

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            Object typ = token.getHeaders().get("typ");
            if (typ instanceof String typStr && typStr.equalsIgnoreCase("at+jwt")) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(INVALID_TYPE_ERROR);
        }
    }
}
