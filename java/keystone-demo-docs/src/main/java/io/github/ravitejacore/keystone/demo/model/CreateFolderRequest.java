package io.github.ravitejacore.keystone.demo.model;

public record CreateFolderRequest(
    String name,
    String parentFolderId
) {
}
