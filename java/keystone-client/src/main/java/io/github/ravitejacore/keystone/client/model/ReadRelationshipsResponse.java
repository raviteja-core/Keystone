package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Response payload for POST /v1/relationships/read.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ReadRelationshipsResponse(
    @JsonProperty("tuples") List<Tuple> tuples,
    @JsonProperty("read_at") String readAt,
    @JsonProperty("continuation_token") String continuationToken
) {
}
