package io.github.ravitejacore.keystone.demo.service;

import io.github.ravitejacore.keystone.demo.model.Doc;
import io.github.ravitejacore.keystone.demo.model.Folder;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class DocRepository {
    private final Map<String, Doc> docs = new ConcurrentHashMap<>();
    private final Map<String, Folder> folders = new ConcurrentHashMap<>();

    public void saveDoc(Doc doc) {
        docs.put(doc.id(), doc);
    }

    public Optional<Doc> findDocById(String id) {
        return Optional.ofNullable(docs.get(id));
    }

    public void deleteDoc(String id) {
        docs.remove(id);
    }

    public void saveFolder(Folder folder) {
        folders.put(folder.id(), folder);
    }

    public Optional<Folder> findFolderById(String id) {
        return Optional.ofNullable(folders.get(id));
    }
}
