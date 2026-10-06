package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class App {

    // SAST Trigger 1: Hardcoded Secret / Credential
    private static final String DB_PASSWORD = "SuperSecretPassword123!";
    private static final String DB_USER = "admin";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";

    public static void main(String[] args) {
        if (args.length > 0) {
            getUserData(args[0]);
            executeUserCommand(args[0]);
        }
    }

    // SAST Trigger 2: SQL Injection (CWE-89)
    public static void getUserData(String inputUsername) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // Unsanitized input concatenated directly into SQL query
            String query = "SELECT * FROM users WHERE username = '" + inputUsername + "'";
            ResultSet rs = stmt.executeQuery(query);

            while (rs.next()) {
                System.out.println("User found: " + rs.getString("username"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // SAST Trigger 3: Command Injection (CWE-78)
    public static void executeUserCommand(String userParam) {
        try {
            // Unsanitized user input passed to OS runtime command execution
            Runtime.getRuntime().exec("ping -c 1 " + userParam);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
