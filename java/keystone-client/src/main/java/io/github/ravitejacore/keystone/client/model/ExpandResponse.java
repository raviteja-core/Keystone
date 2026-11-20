package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response payload for POST /v1/expand.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ExpandResponse(
    @JsonProperty("tree") ExpandTreeNode tree
) {
}
