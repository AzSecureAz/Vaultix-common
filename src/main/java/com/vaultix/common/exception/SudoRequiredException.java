package com.vaultix.common.exception;

public class SudoRequiredException extends RuntimeException {

    public static final String DEFAULT_MESSAGE = "This action requires elevated sudo authentication";

    public SudoRequiredException() {
        super(DEFAULT_MESSAGE);
    }

    public SudoRequiredException(String message) {
        super(message != null && !message.isBlank() ? message : DEFAULT_MESSAGE);
    }

    public SudoRequiredException(String message, Throwable cause) {
        super(message != null && !message.isBlank() ? message : DEFAULT_MESSAGE, cause);
    }
}
