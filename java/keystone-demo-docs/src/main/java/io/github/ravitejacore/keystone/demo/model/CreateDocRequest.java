package io.github.ravitejacore.keystone.demo.model;

public record CreateDocRequest(
    String title,
    String content,
    String folderId
) {
}
