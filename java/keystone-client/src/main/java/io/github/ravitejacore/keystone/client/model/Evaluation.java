package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Execution evaluation metrics for a check query.
 */
public record Evaluation(
    @JsonProperty("depth") int depth,
    @JsonProperty("db_reads") int dbReads
) {
}
