package io.github.ravitejacore.keystone.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientCredentialsTokenProviderTest {

    private HttpServer server;
    private int port;
    private final AtomicInteger requestCount = new AtomicInteger(0);

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();

        server.createContext("/token", exchange -> {
            requestCount.incrementAndGet();

            try (InputStream is = exchange.getRequestBody()) {
                String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);

                if (!body.contains("grant_type=client_credentials") ||
                    !body.contains("client_id=test-client") ||
                    !body.contains("client_secret=test-secret")) {
                    sendResponse(exchange, 401, "{\"error\":\"invalid_client\"}");
                    return;
                }

                String json = "{\"access_token\":\"jwt-m2m-token-12345\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
                sendResponse(exchange, 200, json);
            }
        });

        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("getToken: fetches token on first call and caches for subsequent calls")
    void testTokenCaching() {
        ClientCredentialsTokenProvider provider = ClientCredentialsTokenProvider.builder()
            .tokenUri("http://localhost:" + port + "/token")
            .clientId("test-client")
            .clientSecret("test-secret")
            .scope("authz:check authz:write")
            .build();

        // 1. Initial call -> hits endpoint
        String token1 = provider.getToken();
        assertThat(token1).isEqualTo("jwt-m2m-token-12345");
        assertThat(requestCount.get()).isEqualTo(1);

        // 2. Second call -> served from in-memory cache
        String token2 = provider.getToken();
        assertThat(token2).isEqualTo("jwt-m2m-token-12345");
        assertThat(requestCount.get()).isEqualTo(1);
    }

    @Test
    @DisplayName("getToken: throws KeystoneAuthenticationException on bad credentials")
    void testAuthenticationFailure() {
        ClientCredentialsTokenProvider provider = ClientCredentialsTokenProvider.builder()
            .tokenUri("http://localhost:" + port + "/token")
            .clientId("wrong-client")
            .clientSecret("wrong-secret")
            .build();

        assertThatThrownBy(provider::getToken)
            .isInstanceOf(KeystoneAuthenticationException.class)
            .hasMessageContaining("HTTP 401");
    }

    private void sendResponse(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
