package io.github.ravitejacore.keystone.demo.model;

public record Folder(
    String id,
    String name,
    String parentFolderId,
    String ownerId
) {
}
