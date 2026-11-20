package io.github.ravitejacore.keystone.demo.service;

import io.github.ravitejacore.keystone.client.PermissionClient;
import io.github.ravitejacore.keystone.client.model.Tuple;
import io.github.ravitejacore.keystone.client.model.TupleOperation;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest;
import io.github.ravitejacore.keystone.demo.model.Doc;
import io.github.ravitejacore.keystone.demo.model.Folder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class DocService {

    private final DocRepository repository;
    private final PermissionClient permissionClient;

    public DocService(DocRepository repository, PermissionClient permissionClient) {
        this.repository = repository;
        this.permissionClient = permissionClient;
    }

    public Folder createFolder(String name, String parentFolderId, String ownerId) {
        String id = UUID.randomUUID().toString();
        Folder folder = new Folder(id, name, parentFolderId, ownerId);
        repository.saveFolder(folder);

        List<TupleOperation> ops = new ArrayList<>();
        ops.add(TupleOperation.create(Tuple.of("folder", id, "owner", "user", ownerId)));
        if (parentFolderId != null && !parentFolderId.isBlank()) {
            ops.add(TupleOperation.create(Tuple.of("folder", id, "parent", "folder", parentFolderId)));
        }

        permissionClient.write(WriteRelationshipsRequest.of(ops));
        return folder;
    }

    public Doc createDoc(String title, String content, String folderId, String ownerId) {
        String id = UUID.randomUUID().toString();
        Doc doc = new Doc(id, title, content, folderId, ownerId);
        repository.saveDoc(doc);

        List<TupleOperation> ops = new ArrayList<>();
        ops.add(TupleOperation.create(Tuple.of("doc", id, "owner", "user", ownerId)));
        if (folderId != null && !folderId.isBlank()) {
            ops.add(TupleOperation.create(Tuple.of("doc", id, "parent", "folder", folderId)));
        }

        permissionClient.write(WriteRelationshipsRequest.of(ops));
        return doc;
    }

    public Optional<Doc> getDoc(String id) {
        return repository.findDocById(id);
    }

    public Doc updateDoc(String id, String content) {
        Doc doc = repository.findDocById(id).orElseThrow(() -> new IllegalArgumentException("Doc not found: " + id));
        Doc updated = doc.withUpdatedContent(content);
        repository.saveDoc(updated);
        return updated;
    }

    public void deleteDoc(String id) {
        Doc doc = repository.findDocById(id).orElseThrow(() -> new IllegalArgumentException("Doc not found: " + id));
        repository.deleteDoc(id);

        permissionClient.write(WriteRelationshipsRequest.of(
            TupleOperation.delete(Tuple.of("doc", id, "owner", "user", doc.ownerId()))
        ));
    }

    public void shareDoc(String id, String targetUserId, String relation) {
        permissionClient.write(WriteRelationshipsRequest.of(
            TupleOperation.create(Tuple.of("doc", id, relation, "user", targetUserId))
        ));
    }

    public void unshareDoc(String id, String targetUserId, String relation) {
        if (relation == null || relation.isBlank() || "all".equalsIgnoreCase(relation)) {
            // Revoke all possible sharing relations (editor and viewer)
            permissionClient.write(WriteRelationshipsRequest.of(
                TupleOperation.delete(Tuple.of("doc", id, "editor", "user", targetUserId)),
                TupleOperation.delete(Tuple.of("doc", id, "viewer", "user", targetUserId))
            ));
        } else {
            permissionClient.write(WriteRelationshipsRequest.of(
                TupleOperation.delete(Tuple.of("doc", id, relation, "user", targetUserId))
            ));
        }
    }
}
