package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Identifies a subject in Keystone's authorization graph (concrete user, wildcard, or nested userset).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SubjectRef(
    @JsonProperty("type") String type,
    @JsonProperty("id") String id,
    @JsonProperty("relation") String relation
) {
    public SubjectRef {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(id, "id must not be null");
    }

    public static SubjectRef user(String id) {
        return new SubjectRef("user", id, null);
    }

    public static SubjectRef userset(String type, String id, String relation) {
        return new SubjectRef(type, id, relation);
    }

    public static SubjectRef wildcard(String type) {
        return new SubjectRef(type, "*", null);
    }
}
