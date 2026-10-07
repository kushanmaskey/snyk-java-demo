package com.example;

public class InputValidator {

    public static boolean isNullOrEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    public static boolean isNumeric(String value) {
        if (isNullOrEmpty(value)) {
            return false;
        }
        return value.matches("-?\\d+(\\.\\d+)?");
    }

    public static boolean isWithinLength(String value, int min, int max) {
        if (value == null) {
            return false;
        }
        int len = value.length();
        return len >= min && len <= max;
    }

    public static String truncate(String value, int maxLength) {
        if (value == null) {
            return "";
        }
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    public static boolean containsOnlyAlpha(String value) {
        if (isNullOrEmpty(value)) {
            return false;
        }
        return value.matches("[a-zA-Z]+");
    }

    public static String maskSensitiveData(String value) {
        if (isNullOrEmpty(value)) {
            return "";
        }
        if (value.length() <= 4) {
            return "****";
        }
        return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
    }
}
