package io.github.ravitejacore.keystone.client;

/**
 * Base unchecked exception for all Keystone client errors.
 */
public class KeystoneException extends RuntimeException {
    public KeystoneException(String message) {
        super(message);
    }

    public KeystoneException(String message, Throwable cause) {
        super(message, cause);
    }
}
