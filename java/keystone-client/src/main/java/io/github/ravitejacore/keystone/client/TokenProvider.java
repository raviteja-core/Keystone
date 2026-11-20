package io.github.ravitejacore.keystone.client;

/**
 * Strategy interface for providing OAuth 2.0 Bearer tokens to authenticate API calls against Keystone.
 */
@FunctionalInterface
public interface TokenProvider {
    /**
     * Obtains a valid Bearer token for authenticating service-to-service calls.
     *
     * @return Raw JWT or opaque Bearer token string
     * @throws KeystoneAuthenticationException if token acquisition fails
     */
    String getToken() throws KeystoneAuthenticationException;

    static TokenProvider of(String staticToken) {
        return new StaticTokenProvider(staticToken);
    }
}
