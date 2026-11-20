package io.github.ravitejacore.keystone.client;

/**
 * Exception thrown when authentication or token acquisition with Keystone Auth Server fails.
 */
public class KeystoneAuthenticationException extends KeystoneException {
    public KeystoneAuthenticationException(String message) {
        super(message);
    }

    public KeystoneAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
