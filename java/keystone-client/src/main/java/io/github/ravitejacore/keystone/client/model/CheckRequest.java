package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Request payload for POST /v1/check.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CheckRequest(
    @JsonProperty("object") ResourceRef object,
    @JsonProperty("permission") String permission,
    @JsonProperty("subject") SubjectRef subject,
    @JsonProperty("consistency") Consistency consistency
) {
    public CheckRequest {
        Objects.requireNonNull(object, "object must not be null");
        Objects.requireNonNull(permission, "permission must not be null");
        Objects.requireNonNull(subject, "subject must not be null");
    }

    public static CheckRequest of(ResourceRef object, String permission, SubjectRef subject) {
        return new CheckRequest(object, permission, subject, null);
    }

    public static CheckRequest of(ResourceRef object, String permission, SubjectRef subject, Consistency consistency) {
        return new CheckRequest(object, permission, subject, consistency);
    }
}
