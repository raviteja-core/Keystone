package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Request payload for POST /v1/expand.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ExpandRequest(
    @JsonProperty("object") ResourceRef object,
    @JsonProperty("permission") String permission,
    @JsonProperty("consistency") Consistency consistency
) {
    public ExpandRequest {
        Objects.requireNonNull(object, "object must not be null");
        Objects.requireNonNull(permission, "permission must not be null");
    }

    public static ExpandRequest of(ResourceRef object, String permission) {
        return new ExpandRequest(object, permission, null);
    }

    public static ExpandRequest of(ResourceRef object, String permission, Consistency consistency) {
        return new ExpandRequest(object, permission, consistency);
    }
}
