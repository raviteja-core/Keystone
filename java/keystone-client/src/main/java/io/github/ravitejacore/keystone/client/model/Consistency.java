package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Snapshot consistency options for ReBAC operations.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Consistency(
    @JsonProperty("mode") String mode,
    @JsonProperty("token") String token
) {
    public static final String AT_LEAST_AS_FRESH = "at_least_as_fresh";
    public static final String FULLY_CONSISTENT = "fully_consistent";
    public static final String MINIMIZE_LATENCY = "minimize_latency";

    public static Consistency atLeastAsFresh(String zookie) {
        return new Consistency(AT_LEAST_AS_FRESH, zookie);
    }

    public static Consistency fullyConsistent() {
        return new Consistency(FULLY_CONSISTENT, null);
    }

    public static Consistency minimizeLatency() {
        return new Consistency(MINIMIZE_LATENCY, null);
    }
}
