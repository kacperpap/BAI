package xss;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class vulnerable_xss_papuga implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        Map<String,String> params = queryToMap(query);
        String msg = params.getOrDefault("msg", "");

        String body = "<html><head><meta charset='utf-8'><title>Vulnerable demo</title></head>"
                + "<body><h2>Vulnerable handler (demo)</h2>"
                + "<p>Wysłany tekst:</p>"
                + "<div style='padding:8px;border:1px solid #ccc;'>" + msg + "</div>"
                + "<p><a href=\"/\">Wróć</a></p>"
                + "</body></html>";

        sendResponse(exchange, body);
    }

    private void sendResponse(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String,String> queryToMap(String query) throws UnsupportedEncodingException {
        Map<String,String> result = new HashMap<>();
        if (query == null || query.isEmpty()) return result;
        for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            String key = URLDecoder.decode(pair[0], "UTF-8");
            String value = pair.length > 1 ? URLDecoder.decode(pair[1], "UTF-8") : "";
            result.put(key, value);
        }
        return result;
    }

}
