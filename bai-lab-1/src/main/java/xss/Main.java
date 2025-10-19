package xss;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.net.InetSocketAddress;
import java.io.*;
import java.nio.file.*;

public class Main {
    public static void main(String[] args) throws Exception {
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                byte[] data;
                Path p = Paths.get("src","main","java","xss","index.html");
                if (Files.exists(p)) {
                    data = Files.readAllBytes(p);
                } else {
                    String fallback = "<html><body><p>Brak index.html w katalogu uruchomienia.</p></body></html>";
                    data = fallback.getBytes("UTF-8");
                }
                exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
                exchange.sendResponseHeaders(200, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                }
            }
        });

        server.createContext("/vulnerable", new vulnerable_xss_papuga());
        server.createContext("/fixed", new fixed_xss_papuga());

        server.setExecutor(null);
        server.start();
        System.out.println("Serwer uruchomiony: http://localhost:" + port + "/");
        System.out.println("Użyj formularzy w index.html, aby przetestować endpoints /vulnerable i /fixed");
    }
}
