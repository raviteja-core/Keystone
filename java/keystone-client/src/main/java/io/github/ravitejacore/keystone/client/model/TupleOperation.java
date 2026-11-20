package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Mutation operation on a relationship tuple.
 */
public record TupleOperation(
    @JsonProperty("op") String op,
    @JsonProperty("tuple") Tuple tuple
) {
    public static final String OP_CREATE = "create";
    public static final String OP_TOUCH = "touch";
    public static final String OP_DELETE = "delete";

    public TupleOperation {
        Objects.requireNonNull(op, "op must not be null");
        Objects.requireNonNull(tuple, "tuple must not be null");
    }

    public static TupleOperation create(Tuple tuple) {
        return new TupleOperation(OP_CREATE, tuple);
    }

    public static TupleOperation touch(Tuple tuple) {
        return new TupleOperation(OP_TOUCH, tuple);
    }

    public static TupleOperation delete(Tuple tuple) {
        return new TupleOperation(OP_DELETE, tuple);
    }
}
