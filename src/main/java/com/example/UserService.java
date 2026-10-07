package com.example;

public class UserService {

    public static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        return username.matches("[a-zA-Z0-9_]{3,20}");
    }

    public static String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }
        return input.replaceAll("[^a-zA-Z0-9 ]", "").trim();
    }

    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        return email.contains("@") && email.contains(".");
    }

    public static String formatUsername(String username) {
        if (username == null) {
            return "";
        }
        return username.trim().toLowerCase();
    }

    public static boolean isAdminUser(String username) {
        if (username == null) {
            return false;
        }
        return username.equalsIgnoreCase("admin") || username.equalsIgnoreCase("root");
    }

    public static int getUserAccessLevel(String role) {
        if (role == null) {
            return 0;
        }
        switch (role.toLowerCase()) {
            case "admin": return 3;
            case "editor": return 2;
            case "viewer": return 1;
            default: return 0;
        }
    }
}
