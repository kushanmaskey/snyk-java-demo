package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class App {

    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_URL = System.getenv("DB_URL");

    private static String validateDbUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalStateException("DB_URL environment variable is not set");
        }
        if (!url.startsWith("jdbc:mysql://") && !url.startsWith("jdbc:postgresql://")) {
            throw new IllegalStateException("DB_URL must be a valid JDBC URL for mysql or postgresql");
        }
        return url;
    }
    public static void main(String[] args) {
        if (args.length > 0) {
            getUserData(args[0]);
            executeUserCommand(args[0]);
        }
    }

    public static void getUserData(String inputUsername) {
        try {
            Connection conn = DriverManager.getConnection(validateDbUrl(DB_URL), DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String query = "SELECT * FROM users WHERE username = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, inputUsername);
            
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                System.out.println("User found: " + rs.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void executeUserCommand(String userParam) {
        if (userParam == null || !userParam.matches("[a-zA-Z0-9.\\-]+")) {
            throw new IllegalArgumentException("Invalid host parameter");
        }
        try {
            Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", userParam});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
