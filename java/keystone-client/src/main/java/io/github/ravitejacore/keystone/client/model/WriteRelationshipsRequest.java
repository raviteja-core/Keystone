package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Objects;

/**
 * Request payload for POST /v1/relationships/write.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WriteRelationshipsRequest(
    @JsonProperty("operations") List<TupleOperation> operations,
    @JsonProperty("preconditions") List<Precondition> preconditions
) {
    public WriteRelationshipsRequest {
        Objects.requireNonNull(operations, "operations must not be null");
    }

    public static WriteRelationshipsRequest of(List<TupleOperation> operations) {
        return new WriteRelationshipsRequest(operations, null);
    }

    public static WriteRelationshipsRequest of(TupleOperation... operations) {
        return new WriteRelationshipsRequest(List.of(operations), null);
    }

    public static WriteRelationshipsRequest of(List<TupleOperation> operations, List<Precondition> preconditions) {
        return new WriteRelationshipsRequest(operations, preconditions);
    }
}
