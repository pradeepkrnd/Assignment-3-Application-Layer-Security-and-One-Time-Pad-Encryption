import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Local teaching demo of defensive controls at OSI layer 7. NOT a production server. */
public class ApplicationLayerSecurity {
    private static final int MAX_BODY_BYTES = 1024;
    private static final Map<String, Window> WINDOWS = new ConcurrentHashMap<>();
    private static final class Window {
        final long start = System.currentTimeMillis();
        final AtomicInteger count = new AtomicInteger();
    }
    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 18081), 0);
        server.createContext("/api/message", ApplicationLayerSecurity::handle);
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("Layer 7 demo listening on http://127.0.0.1:18081/api/message");
    }
    private static void handle(HttpExchange ex) throws IOException {
        try {
            ex.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
            ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            ex.getResponseHeaders().set("X-Frame-Options", "DENY");
            ex.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
            ex.getResponseHeaders().set("Cache-Control", "no-store");
            if (!allow(ex.getRemoteAddress().getAddress().getHostAddress())) {
                respond(ex, 429, "Rate limit exceeded"); return;
            }
            if (!"POST".equals(ex.getRequestMethod())) {
                ex.getResponseHeaders().set("Allow", "POST");
                respond(ex, 405, "Only POST is allowed"); return;
            }
            String ct = ex.getRequestHeaders().getFirst("Content-Type");
            if (ct == null || !ct.equalsIgnoreCase("text/plain; charset=utf-8")) {
                respond(ex, 415, "Use Content-Type: text/plain; charset=utf-8"); return;
            }
            byte[] body;
            try (InputStream in = ex.getRequestBody()) {
                body = in.readNBytes(MAX_BODY_BYTES + 1);
            }
            if (body.length > MAX_BODY_BYTES) {
                respond(ex, 413, "Request body too large"); return;
            }
            String message = new String(body, StandardCharsets.UTF_8);
            if (!message.matches("[A-Za-z0-9 ]{1,80}")) {
                respond(ex, 400, "Invalid message: letters, digits, spaces only (1-80)"); return;
            }
            respond(ex, 200, "Accepted message length: " + message.length());
        } finally { ex.close(); }
    }
    private static boolean allow(String ip) {
        long now = System.currentTimeMillis();
        Window w = WINDOWS.compute(ip, (k, old) -> old == null || now - old.start >= 60_000 ? new Window() : old);
        return w.count.incrementAndGet() <= 30;
    }
    private static void respond(HttpExchange ex, int code, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, bytes.length);
        try (var out = ex.getResponseBody()) { out.write(bytes); }
    }
}
