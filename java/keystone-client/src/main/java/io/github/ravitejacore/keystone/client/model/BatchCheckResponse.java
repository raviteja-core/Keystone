package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Response payload for POST /v1/check/batch.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BatchCheckResponse(
    @JsonProperty("checked_at") String checkedAt,
    @JsonProperty("results") List<BatchCheckItemResult> results
) {
}
