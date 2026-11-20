package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Normalized relationship tuple in Keystone.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Tuple(
    @JsonProperty("object_type") String objectType,
    @JsonProperty("object_id") String objectId,
    @JsonProperty("relation") String relation,
    @JsonProperty("subject_type") String subjectType,
    @JsonProperty("subject_id") String subjectId,
    @JsonProperty("subject_relation") String subjectRelation
) {
    public Tuple {
        Objects.requireNonNull(objectType, "objectType must not be null");
        Objects.requireNonNull(objectId, "objectId must not be null");
        Objects.requireNonNull(relation, "relation must not be null");
        Objects.requireNonNull(subjectType, "subjectType must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
    }

    public static Tuple of(String objectType, String objectId, String relation, String subjectType, String subjectId) {
        return new Tuple(objectType, objectId, relation, subjectType, subjectId, null);
    }

    public static Tuple userset(String objectType, String objectId, String relation, String subjectType, String subjectId, String subjectRelation) {
        return new Tuple(objectType, objectId, relation, subjectType, subjectId, subjectRelation);
    }
}
