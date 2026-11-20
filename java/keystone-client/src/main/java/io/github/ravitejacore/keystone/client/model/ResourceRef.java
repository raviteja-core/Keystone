package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Identifies a resource object in Keystone's authorization graph (e.g. document:123).
 */
public record ResourceRef(
    @JsonProperty("type") String type,
    @JsonProperty("id") String id
) {
    public ResourceRef {
        Objects.requireNonNull(type, "type must not be null");
        Objects.requireNonNull(id, "id must not be null");
    }

    public static ResourceRef of(String type, String id) {
        return new ResourceRef(type, id);
    }
}
