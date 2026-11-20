package io.github.ravitejacore.keystone.client;

import io.github.ravitejacore.keystone.client.model.ProblemDetails;
import java.util.Objects;

/**
 * Exception thrown when the Keystone Authz service returns an RFC 9457 Problem Details error.
 */
public class KeystoneProblemException extends KeystoneException {
    private final ProblemDetails problem;

    public KeystoneProblemException(ProblemDetails problem) {
        super(Objects.requireNonNull(problem, "problem must not be null").toDisplayString());
        this.problem = problem;
    }

    public ProblemDetails getProblem() {
        return problem;
    }

    public int getStatus() {
        return problem.status();
    }

    public String getTitle() {
        return problem.title();
    }

    public String getDetail() {
        return problem.detail();
    }
}
