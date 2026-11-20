package io.github.ravitejacore.keystone.demo.model;

public record Doc(
    String id,
    String title,
    String content,
    String folderId,
    String ownerId
) {
    public Doc withUpdatedContent(String newContent) {
        return new Doc(id, title, newContent, folderId, ownerId);
    }
}
