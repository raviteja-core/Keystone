package io.github.ravitejacore.keystone.client;

import java.util.Objects;

/**
 * Static token provider returning a pre-configured token string.
 */
public class StaticTokenProvider implements TokenProvider {
    private final String token;

    public StaticTokenProvider(String token) {
        this.token = Objects.requireNonNull(token, "token must not be null");
    }

    @Override
    public String getToken() {
        return token;
    }
}
