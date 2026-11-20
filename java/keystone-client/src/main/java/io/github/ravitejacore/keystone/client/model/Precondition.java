package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Precondition required for relationship mutations.
 */
public record Precondition(
    @JsonProperty("tuple") Tuple tuple,
    @JsonProperty("exists") boolean exists
) {
    public Precondition {
        Objects.requireNonNull(tuple, "tuple must not be null");
    }

    public static Precondition mustExist(Tuple tuple) {
        return new Precondition(tuple, true);
    }

    public static Precondition mustNotExist(Tuple tuple) {
        return new Precondition(tuple, false);
    }
}
