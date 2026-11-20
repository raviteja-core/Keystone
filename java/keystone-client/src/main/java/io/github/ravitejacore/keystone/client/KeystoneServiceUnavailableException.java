package io.github.ravitejacore.keystone.client;

/**
 * Exception thrown when the Keystone Authz service is unreachable or encounters a network timeout.
 * Keystone fails closed: service failures must never result in granted permissions.
 */
public class KeystoneServiceUnavailableException extends KeystoneException {
    public KeystoneServiceUnavailableException(String message) {
        super(message);
    }

    public KeystoneServiceUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
