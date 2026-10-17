package com.example;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class VulnerableHttpServer {

    static final int PORT = 8082;

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/",       new HomeHandler());
        server.createContext("/health", new HealthHandler());
        server.createContext("/search", new SearchHandler());
        server.createContext("/user",   new UserHandler());
        server.createContext("/ping",   new PingHandler());
        server.createContext("/fetch",  new FetchHandler());
        server.start();
        System.out.println("VulnerableHttpServer started on port " + PORT);
    }

    static void send(HttpExchange ex, int code, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.getResponseHeaders().set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
        ex.getResponseHeaders().set("Cross-Origin-Embedder-Policy", "require-corp");
        ex.getResponseHeaders().set("Cross-Origin-Opener-Policy", "same-origin");
        ex.getResponseHeaders().set("Cross-Origin-Resource-Policy", "same-origin");
        ex.getResponseHeaders().set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)");
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        ex.getResponseHeaders().set("X-Frame-Options", "DENY");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    static String queryParam(String query, String key) {
        if (query == null) return "";
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && kv[0].equals(key)) {
                try { return URLDecoder.decode(kv[1], StandardCharsets.UTF_8); }
                catch (Exception e) { return kv[1]; }
            }
        }
        return "";
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            send(ex, 200, "text/plain", "OK");
        }
    }

    static class HomeHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            ex.getResponseHeaders().add("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Strict");
            ex.getResponseHeaders().add("Set-Cookie", "user=admin; Path=/; HttpOnly; SameSite=Strict");
            String html = "<html><body><h1>Demo App</h1><ul>" +
                "<li><a href='/search?q=hello'>Search</a></li>" +
                "<li><a href='/user?name=admin'>User Lookup</a></li>" +
                "<li><a href='/ping?host=localhost'>Ping</a></li>" +
                "<li><a href='/fetch?url=http://localhost:8082/health'>Fetch</a></li>" +
                "</ul></body></html>";
            send(ex, 200, "text/html", html);
        }
    }

    static class SearchHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String q = queryParam(ex.getRequestURI().getQuery(), "q");
            // Insecure cookie on search results page — ZAP Plugin 10010 and 10011
            ex.getResponseHeaders().add("Set-Cookie", "search_session=xyz789; Path=/; HttpOnly; SameSite=Strict");
            // XSS: reflects user input directly into HTML without encoding
            String html = "<html><body><h2>Search Results</h2><p>You searched for: " + q + "</p></body></html>";
            send(ex, 200, "text/html", html);
        }
    }

    static class UserHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String name = queryParam(ex.getRequestURI().getQuery(), "name");
            String html = "<html><body><h2>User Lookup</h2><p>User: " + name + "</p></body></html>";
            send(ex, 200, "text/html", html);
        }
    }

    static class PingHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String host = queryParam(ex.getRequestURI().getQuery(), "host");
            // Command Injection: concatenates user input into a shell command
            String output;
            try {
                Process p = Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
                output = sb.toString();
            } catch (Exception e) {
                output = "Error: " + e.getMessage();
            }
            String html = "<html><body><h2>Ping</h2><pre>" + output + "</pre></body></html>";
            send(ex, 200, "text/html", html);
        }
    }

    static class FetchHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String url = queryParam(ex.getRequestURI().getQuery(), "url");
            // SSRF: fetches arbitrary URLs without validation
            String content;
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
                content = sb.toString();
            } catch (Exception e) {
                content = "Error: " + e.getMessage();
            }
            String html = "<html><body><h2>Fetch</h2><pre>" + content + "</pre></body></html>";
            send(ex, 200, "text/html", html);
        }
    }
}
