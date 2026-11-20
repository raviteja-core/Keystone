package io.github.ravitejacore.keystone.demo.controller;

import io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermission;
import io.github.ravitejacore.keystone.demo.model.CreateDocRequest;
import io.github.ravitejacore.keystone.demo.model.CreateFolderRequest;
import io.github.ravitejacore.keystone.demo.model.Doc;
import io.github.ravitejacore.keystone.demo.model.Folder;
import io.github.ravitejacore.keystone.demo.model.ShareRequest;
import io.github.ravitejacore.keystone.demo.service.DocService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping
public class DocController {

    private final DocService docService;

    public DocController(DocService docService) {
        this.docService = docService;
    }

    @GetMapping("/me")
    public Map<String, Object> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
            "sub", jwt.getSubject(),
            "username", jwt.getClaimAsString("preferred_username") != null ? jwt.getClaimAsString("preferred_username") : jwt.getSubject(),
            "scope", jwt.getClaimAsString("scope") != null ? jwt.getClaimAsString("scope") : ""
        );
    }

    @PostMapping("/folders")
    public ResponseEntity<Folder> createFolder(@RequestBody CreateFolderRequest request,
                                               @AuthenticationPrincipal Jwt jwt) {
        Folder folder = docService.createFolder(request.name(), request.parentFolderId(), jwt.getSubject());
        return ResponseEntity.status(HttpStatus.CREATED).body(folder);
    }

    @PostMapping("/docs")
    public ResponseEntity<Doc> createDoc(@RequestBody CreateDocRequest request,
                                         @AuthenticationPrincipal Jwt jwt) {
        Doc doc = docService.createDoc(request.title(), request.content(), request.folderId(), jwt.getSubject());
        return ResponseEntity.status(HttpStatus.CREATED).body(doc);
    }

    @GetMapping("/docs/{id}")
    @RequiresPermission(type = "doc", id = "#id", permission = "view")
    public ResponseEntity<Doc> getDoc(@PathVariable String id) {
        return docService.getDoc(id)
            .map(ResponseEntity::ok)
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping("/docs/{id}")
    @RequiresPermission(type = "doc", id = "#id", permission = "edit")
    public ResponseEntity<Doc> updateDoc(@PathVariable String id, @RequestBody Map<String, String> body) {
        String newContent = body.getOrDefault("content", "");
        Doc updated = docService.updateDoc(id, newContent);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/docs/{id}")
    @RequiresPermission(type = "doc", id = "#id", permission = "delete")
    public ResponseEntity<Void> deleteDoc(@PathVariable String id) {
        docService.deleteDoc(id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/docs/{id}/share")
    @RequiresPermission(type = "doc", id = "#id", permission = "edit")
    public ResponseEntity<Map<String, String>> shareDoc(@PathVariable String id, @RequestBody ShareRequest request) {
        docService.shareDoc(id, request.targetUserId(), request.relation());
        return ResponseEntity.ok(Map.of(
            "status", "shared",
            "docId", id,
            "targetUser", request.targetUserId(),
            "relation", request.relation()
        ));
    }

    @PostMapping("/docs/{id}/unshare")
    @RequiresPermission(type = "doc", id = "#id", permission = "edit")
    public ResponseEntity<Map<String, String>> unshareDoc(@PathVariable String id, @RequestBody ShareRequest request) {
        docService.unshareDoc(id, request.targetUserId(), request.relation());
        return ResponseEntity.ok(Map.of(
            "status", "unshared",
            "docId", id,
            "targetUser", request.targetUserId(),
            "relation", request.relation()
        ));
    }
}
