package com.filetransfer.common.http;

import com.filetransfer.common.json.SimpleJson;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class Responses {

    private Responses() {
    }

    public static void sendJson(HttpExchange exchange, int status, Map<String, ?> body) throws IOException {
        byte[] bytes = SimpleJson.writeFlatObject(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
