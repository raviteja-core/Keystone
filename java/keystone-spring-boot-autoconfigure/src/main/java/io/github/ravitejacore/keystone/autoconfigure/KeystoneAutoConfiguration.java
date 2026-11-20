package io.github.ravitejacore.keystone.autoconfigure;

import io.github.ravitejacore.keystone.autoconfigure.security.KeystoneJwtConfiguration;
import io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermissionAspect;
import io.github.ravitejacore.keystone.client.ClientCredentialsTokenProvider;
import io.github.ravitejacore.keystone.client.PermissionClient;
import io.github.ravitejacore.keystone.client.TokenProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.net.URI;

/**
 * Spring Boot auto-configuration for Keystone IAM and ReBAC client.
 */
@AutoConfiguration
@EnableConfigurationProperties(KeystoneProperties.class)
@ConditionalOnProperty(prefix = "keystone", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import(KeystoneJwtConfiguration.class)
public class KeystoneAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "keystone.authz", name = {"url", "client-id", "client-secret"})
    public TokenProvider keystoneTokenProvider(KeystoneProperties properties) {
        URI tokenUri = URI.create(properties.getIssuerUri().toString().replaceAll("/+$", "") + "/token");
        return ClientCredentialsTokenProvider.builder()
            .tokenUri(tokenUri)
            .clientId(properties.getAuthz().getClientId())
            .clientSecret(properties.getAuthz().getClientSecret())
            .scope(properties.getAuthz().getScope())
            .build();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "keystone.authz", name = "url")
    public PermissionClient keystonePermissionClient(KeystoneProperties properties,
                                                     org.springframework.beans.factory.ObjectProvider<TokenProvider> tokenProvider) {
        PermissionClient.Builder builder = PermissionClient.builder()
            .baseUrl(properties.getAuthz().getUrl())
            .timeout(properties.getAuthz().getTimeout());

        tokenProvider.ifAvailable(builder::tokenProvider);

        PermissionClient rawClient = builder.build();

        if (properties.getAuthz().getCache().isEnabled()) {
            return new CachedPermissionClient(
                rawClient,
                properties.getAuthz().getCache().getTtl(),
                properties.getAuthz().getCache().getMaxSize()
            );
        }

        return rawClient;
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(org.aspectj.lang.annotation.Aspect.class)
    public RequiresPermissionAspect requiresPermissionAspect(PermissionClient permissionClient, KeystoneProperties properties) {
        return new RequiresPermissionAspect(permissionClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(HealthIndicator.class)
    public KeystoneHealthIndicator keystoneHealthIndicator(KeystoneProperties properties) {
        return new KeystoneHealthIndicator(properties);
    }
}
