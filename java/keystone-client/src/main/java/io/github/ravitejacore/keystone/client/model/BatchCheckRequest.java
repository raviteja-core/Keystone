package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Objects;

/**
 * Request payload for POST /v1/check/batch.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record BatchCheckRequest(
    @JsonProperty("checks") List<CheckRequest> checks,
    @JsonProperty("consistency") Consistency consistency
) {
    public BatchCheckRequest {
        Objects.requireNonNull(checks, "checks list must not be null");
        if (checks.isEmpty()) {
            throw new IllegalArgumentException("checks list must not be empty");
        }
    }

    public static BatchCheckRequest of(List<CheckRequest> checks) {
        return new BatchCheckRequest(checks, null);
    }

    public static BatchCheckRequest of(List<CheckRequest> checks, Consistency consistency) {
        return new BatchCheckRequest(checks, consistency);
    }
}
