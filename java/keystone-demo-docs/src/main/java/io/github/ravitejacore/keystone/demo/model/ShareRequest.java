package io.github.ravitejacore.keystone.demo.model;

public record ShareRequest(
    String targetUserId,
    String relation // "editor" or "viewer"
) {
}
