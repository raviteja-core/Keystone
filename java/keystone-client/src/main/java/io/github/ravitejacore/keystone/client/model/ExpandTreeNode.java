package io.github.ravitejacore.keystone.client.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Node in an expanded ReBAC permission tree.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ExpandTreeNode(
    @JsonProperty("type") String type, // "leaf", "union", "intersection", "exclusion"
    @JsonProperty("target") ResourceRef target,
    @JsonProperty("relation") String relation,
    @JsonProperty("subject") SubjectRef subject,
    @JsonProperty("children") List<ExpandTreeNode> children
) {
}
