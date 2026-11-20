package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * RFC 9457 Problem Details for HTTP APIs returned by Keystone services.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProblemDetails(
    @JsonProperty("type") String type,
    @JsonProperty("title") String title,
    @JsonProperty("status") int status,
    @JsonProperty("detail") String detail,
    @JsonProperty("instance") String instance
) {
    public String toDisplayString() {
        if (detail != null && !detail.isBlank()) {
            return String.format("%d %s: %s", status, title, detail);
        }
        return String.format("%d %s", status, title);
    }
}
