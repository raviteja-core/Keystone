package io.github.ravitejacore.keystone.autoconfigure;

import io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermission;
import io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermissionAspect;
import io.github.ravitejacore.keystone.client.KeystoneServiceUnavailableException;
import io.github.ravitejacore.keystone.client.PermissionClient;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.Evaluation;
import io.github.ravitejacore.keystone.client.model.ResourceRef;
import io.github.ravitejacore.keystone.client.model.SubjectRef;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequiresPermissionAspectTest {

    interface DocumentService {
        String viewDocument(String id);
        String viewWithCompoundSpel(String id);
        void updateDocument(String id, String content);
    }

    static class DocumentServiceImpl implements DocumentService {
        @Override
        @RequiresPermission(type = "document", id = "#id", permission = "view")
        public String viewDocument(String id) {
            return "Document content: " + id;
        }

        @Override
        @RequiresPermission(type = "document", id = "'prefix-' + #id", permission = "view")
        public String viewWithCompoundSpel(String id) {
            return "Compound: " + id;
        }

        @Override
        @RequiresPermission(type = "document", id = "#id", permission = "edit")
        public void updateDocument(String id, String content) {
        }
    }

    static class MockPermissionClient implements PermissionClient {
        boolean allow = true;
        boolean throwError = false;
        CheckRequest lastRequest;

        @Override
        public CheckResponse check(CheckRequest request) {
            this.lastRequest = request;
            if (throwError) {
                throw new KeystoneServiceUnavailableException("Connection refused");
            }
            return new CheckResponse(allow, "2026-11-20T10:00:00Z", new Evaluation(1, 1));
        }

        @Override public io.github.ravitejacore.keystone.client.model.BatchCheckResponse batchCheck(io.github.ravitejacore.keystone.client.model.BatchCheckRequest request) { return null; }
        @Override public io.github.ravitejacore.keystone.client.model.WriteRelationshipsResponse write(io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest request) { return null; }
        @Override public io.github.ravitejacore.keystone.client.model.ReadRelationshipsResponse read(io.github.ravitejacore.keystone.client.model.ReadRelationshipsRequest request) { return null; }
        @Override public io.github.ravitejacore.keystone.client.model.ExpandResponse expand(io.github.ravitejacore.keystone.client.model.ExpandRequest request) { return null; }
        @Override public String getLatestZookie() { return null; }
        @Override public void setLatestZookie(String zookie) {}
    }

    private MockPermissionClient mockClient;
    private DocumentService proxy;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.getContext().setAuthentication(
            new TestingAuthenticationToken("alice", "password", "ROLE_USER")
        );

        mockClient = new MockPermissionClient();
        KeystoneProperties props = new KeystoneProperties();
        RequiresPermissionAspect aspect = new RequiresPermissionAspect(mockClient, props);

        AspectJProxyFactory factory = new AspectJProxyFactory(new DocumentServiceImpl());
        factory.setProxyTargetClass(true);
        factory.addAspect(aspect);
        proxy = factory.getProxy();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Allowed permission executes method and passes correct SpEL arguments to check")
    void allowedPermissionExecutesMethod() {
        mockClient.allow = true;

        String result = proxy.viewDocument("doc-99");
        assertThat(result).isEqualTo("Document content: doc-99");

        assertThat(mockClient.lastRequest.object()).isEqualTo(ResourceRef.of("document", "doc-99"));
        assertThat(mockClient.lastRequest.permission()).isEqualTo("view");
        assertThat(mockClient.lastRequest.subject()).isEqualTo(SubjectRef.user("alice"));
    }

    @Test
    @DisplayName("Denied permission throws AccessDeniedException (HTTP 403)")
    void deniedPermissionThrowsAccessDenied() {
        mockClient.allow = false;

        assertThatThrownBy(() -> proxy.viewDocument("doc-secret"))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Access Denied");
    }

    @Test
    @DisplayName("Compound SpEL expression evaluates properly (prefix- + #id)")
    void compoundSpelExpressionEvaluates() {
        mockClient.allow = true;

        String res = proxy.viewWithCompoundSpel("100");
        assertThat(res).isEqualTo("Compound: 100");
        assertThat(mockClient.lastRequest.object().id()).isEqualTo("prefix-100");
    }

    @Test
    @DisplayName("Anonymous user token is rejected as unauthenticated")
    void anonymousUserIsRejected() {
        SecurityContextHolder.getContext().setAuthentication(
            new org.springframework.security.authentication.AnonymousAuthenticationToken(
                "key", "anonymousUser", org.springframework.security.core.authority.AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
            )
        );

        assertThatThrownBy(() -> proxy.viewDocument("doc-1"))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Unauthenticated or anonymous");
    }
}
