package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response payload for POST /v1/relationships/write.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record WriteRelationshipsResponse(
    @JsonProperty("zookie") String zookie
) {
}
