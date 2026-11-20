package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response payload for POST /v1/check.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CheckResponse(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("checked_at") String checkedAt,
    @JsonProperty("evaluation") Evaluation evaluation
) {
}
