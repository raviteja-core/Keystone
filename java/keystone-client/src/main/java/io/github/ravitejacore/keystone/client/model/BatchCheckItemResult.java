package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Single evaluation result in a batch check response.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BatchCheckItemResult(
    @JsonProperty("allowed") boolean allowed,
    @JsonProperty("evaluation") Evaluation evaluation,
    @JsonProperty("error") String error
) {
}
