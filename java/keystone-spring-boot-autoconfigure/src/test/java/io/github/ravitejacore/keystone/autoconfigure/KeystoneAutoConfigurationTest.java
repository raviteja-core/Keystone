package io.github.ravitejacore.keystone.autoconfigure;

import io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermissionAspect;
import io.github.ravitejacore.keystone.client.PermissionClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class KeystoneAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(KeystoneAutoConfiguration.class));

    @Test
    @DisplayName("Auto-configuration activates when authz.url is configured")
    void activatesWithProperties() {
        contextRunner
            .withPropertyValues(
                "keystone.issuer-uri=http://localhost:8080",
                "keystone.audience=demo-docs",
                "keystone.authz.url=http://localhost:8081"
            )
            .run(context -> {
                assertThat(context).hasSingleBean(PermissionClient.class);
                assertThat(context).hasSingleBean(RequiresPermissionAspect.class);
            });
    }

    @Test
    @DisplayName("Auto-configuration backs off when keystone.enabled=false")
    void backsOffWhenDisabled() {
        contextRunner
            .withPropertyValues(
                "keystone.enabled=false",
                "keystone.authz.url=http://localhost:8081"
            )
            .run(context -> {
                assertThat(context).doesNotHaveBean(PermissionClient.class);
                assertThat(context).doesNotHaveBean(RequiresPermissionAspect.class);
            });
    }

    @Test
    @DisplayName("User-defined PermissionClient bean backs off auto-configuration")
    void userBeanTakesPrecedence() {
        contextRunner
            .withUserConfiguration(CustomClientConfiguration.class)
            .withPropertyValues(
                "keystone.authz.url=http://localhost:8081"
            )
            .run(context -> {
                assertThat(context).hasSingleBean(PermissionClient.class);
                assertThat(context.getBean(PermissionClient.class)).isSameAs(CustomClientConfiguration.customClient);
            });
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomClientConfiguration {
        static final PermissionClient customClient = PermissionClient.builder().baseUrl("http://localhost:9999").build();

        @Bean
        PermissionClient customPermissionClient() {
            return customClient;
        }
    }
}

