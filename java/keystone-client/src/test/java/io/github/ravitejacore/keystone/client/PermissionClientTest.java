package io.github.ravitejacore.keystone.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import io.github.ravitejacore.keystone.client.model.BatchCheckItemResult;
import io.github.ravitejacore.keystone.client.model.BatchCheckRequest;
import io.github.ravitejacore.keystone.client.model.BatchCheckResponse;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.Consistency;
import io.github.ravitejacore.keystone.client.model.Evaluation;
import io.github.ravitejacore.keystone.client.model.ExpandRequest;
import io.github.ravitejacore.keystone.client.model.ExpandResponse;
import io.github.ravitejacore.keystone.client.model.ExpandTreeNode;
import io.github.ravitejacore.keystone.client.model.ProblemDetails;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.ReadRelationshipsResponse;
import io.github.ravitejacore.keystone.client.model.ResourceRef;
import io.github.ravitejacore.keystone.client.model.SubjectRef;
import io.github.ravitejacore.keystone.client.model.Tuple;
import io.github.ravitejacore.keystone.client.model.TupleOperation;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsRequest;
import io.github.ravitejacore.keystone.client.model.WriteRelationshipsResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionClientTest {

    private HttpServer server;
    private int port;
    private PermissionClient client;
    private final ObjectMapper mapper = new ObjectMapper();

    private final AtomicBoolean return500 = new AtomicBoolean(false);
    private final AtomicInteger checkCalls = new AtomicInteger(0);

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();

        server.createContext("/v1/check", exchange -> {
            if (return500.get()) {
                sendResponse(exchange, 500, "{\"error\":\"database down\"}");
                return;
            }

            checkCalls.incrementAndGet();
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                sendResponse(exchange, 401, "{\"error\":\"unauthorized\"}");
                return;
            }

            try (InputStream is = exchange.getRequestBody()) {
                CheckRequest req = mapper.readValue(is, CheckRequest.class);
                boolean allowed = "allowed-doc".equals(req.object().id());

                exchange.getResponseHeaders().set("X-Keystone-Zookie", "zk:test:rev-42");
                CheckResponse resp = new CheckResponse(allowed, "2026-11-20T10:00:00Z", new Evaluation(2, 1));
                sendResponse(exchange, 200, mapper.writeValueAsString(resp));
            }
        });

        server.createContext("/v1/check/batch", exchange -> {
            try (InputStream is = exchange.getRequestBody()) {
                BatchCheckRequest req = mapper.readValue(is, BatchCheckRequest.class);
                List<BatchCheckItemResult> results = req.checks().stream()
                    .map(c -> new BatchCheckItemResult("allowed-doc".equals(c.object().id()), new Evaluation(1, 1), null))
                    .toList();
                BatchCheckResponse resp = new BatchCheckResponse("2026-11-20T10:00:00Z", results);
                sendResponse(exchange, 200, mapper.writeValueAsString(resp));
            }
        });

        server.createContext("/v1/relationships/write", exchange -> {
            exchange.getResponseHeaders().set("X-Keystone-Zookie", "zk:test:rev-43");
            WriteRelationshipsResponse resp = new WriteRelationshipsResponse("zk:test:rev-43");
            sendResponse(exchange, 200, mapper.writeValueAsString(resp));
        });

        server.createContext("/v1/relationships/read", exchange -> {
            List<Tuple> tuples = List.of(Tuple.of("doc", "doc1", "owner", "user", "alice"));
            ReadRelationshipsResponse resp = new ReadRelationshipsResponse(tuples, "2026-11-20T10:00:00Z", "cont-tok-1");
            sendResponse(exchange, 200, mapper.writeValueAsString(resp));
        });

        server.createContext("/v1/expand", exchange -> {
            ExpandTreeNode root = new ExpandTreeNode("leaf", ResourceRef.of("doc", "doc1"), "owner", SubjectRef.user("alice"), List.of());
            ExpandResponse resp = new ExpandResponse(root);
            sendResponse(exchange, 200, mapper.writeValueAsString(resp));
        });

        server.createContext("/v1/problem-test", exchange -> {
            ProblemDetails prob = new ProblemDetails(
                "https://keystone.auth/errors/unknown-relation",
                "Unknown Relation",
                400,
                "Relation 'invalid' does not exist in schema",
                "/v1/check"
            );
            exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
            sendResponse(exchange, 400, mapper.writeValueAsString(prob));
        });

        server.start();

        client = PermissionClient.builder()
            .baseUrl("http://localhost:" + port)
            .tokenProvider(TokenProvider.of("test-secret-token"))
            .timeout(Duration.ofSeconds(3))
            .build();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("check: granted and denied permission evaluation with Zookie capture")
    void testCheckAllowedAndDenied() {
        // 1. Allowed check
        CheckResponse respAllowed = client.check(CheckRequest.of(
            ResourceRef.of("doc", "allowed-doc"),
            "view",
            SubjectRef.user("alice")
        ));
        assertThat(respAllowed.allowed()).isTrue();
        assertThat(respAllowed.evaluation().depth()).isEqualTo(2);
        assertThat(client.getLatestZookie()).isEqualTo("zk:test:rev-42");

        // 2. Denied check
        boolean denied = client.check(
            ResourceRef.of("doc", "secret-doc"),
            "view",
            SubjectRef.user("bob")
        );
        assertThat(denied).isFalse();
    }

    @Test
    @DisplayName("batchCheck: processes multiple checks in one round-trip")
    void testBatchCheck() {
        BatchCheckResponse resp = client.batchCheck(BatchCheckRequest.of(List.of(
            CheckRequest.of(ResourceRef.of("doc", "allowed-doc"), "view", SubjectRef.user("alice")),
            CheckRequest.of(ResourceRef.of("doc", "denied-doc"), "view", SubjectRef.user("bob"))
        )));

        assertThat(resp.results()).hasSize(2);
        assertThat(resp.results().get(0).allowed()).isTrue();
        assertThat(resp.results().get(1).allowed()).isFalse();
    }

    @Test
    @DisplayName("write: mutates tuples and captures updated Zookie")
    void testWriteRelationships() {
        WriteRelationshipsResponse resp = client.write(WriteRelationshipsRequest.of(
            TupleOperation.create(Tuple.of("doc", "doc1", "owner", "user", "alice"))
        ));

        assertThat(resp.zookie()).isEqualTo("zk:test:rev-43");
        assertThat(client.getLatestZookie()).isEqualTo("zk:test:rev-43");
    }

    @Test
    @DisplayName("read: returns matching tuples")
    void testReadRelationships() {
        ReadRelationshipsResponse resp = client.read(ReadRelationshipsRequest.builder()
            .object("doc", "doc1")
            .relation("owner")
            .build());

        assertThat(resp.tuples()).hasSize(1);
        assertThat(resp.tuples().get(0).subjectId()).isEqualTo("alice");
        assertThat(resp.continuationToken()).isEqualTo("cont-tok-1");
    }

    @Test
    @DisplayName("expand: parses userset expansion tree")
    void testExpand() {
        ExpandResponse resp = client.expand(ExpandRequest.of(ResourceRef.of("doc", "doc1"), "owner"));
        assertThat(resp.tree()).isNotNull();
        assertThat(resp.tree().type()).isEqualTo("leaf");
        assertThat(resp.tree().subject().id()).isEqualTo("alice");
    }

    @Test
    @DisplayName("fail-closed: backend 500 error throws KeystoneServiceUnavailableException")
    void testFailClosedOn500() {
        return500.set(true);

        assertThatThrownBy(() -> client.check(ResourceRef.of("doc", "allowed-doc"), "view", SubjectRef.user("alice")))
            .isInstanceOf(KeystoneException.class);
    }

    @Test
    @DisplayName("fail-closed: unreachable backend throws KeystoneServiceUnavailableException")
    void testFailClosedOnUnreachable() {
        PermissionClient unreachableClient = PermissionClient.builder()
            .baseUrl("http://localhost:64999") // Unused port
            .tokenProvider(TokenProvider.of("tok"))
            .timeout(Duration.ofMillis(300))
            .build();

        assertThatThrownBy(() -> unreachableClient.check(ResourceRef.of("doc", "1"), "view", SubjectRef.user("alice")))
            .isInstanceOf(KeystoneServiceUnavailableException.class);
    }

    private void sendResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes();
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
