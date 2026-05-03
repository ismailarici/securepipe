package com.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class App {

    // Hardcoded credentials — intentional vulnerability for demo
    private static final String DB_URL = "jdbc:mysql://localhost:3306/app";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecret123!";

    public static String getUser(String userId) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // SQL injection — string concatenation instead of parameterised query
        String query = "SELECT * FROM users WHERE id = " + userId;
        return stmt.executeQuery(query).toString();
    }

    public static Object deserialize(byte[] data) throws Exception {
        // Insecure deserialization
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    public static void runCommand(String input) throws IOException {
        // OS command injection — user input passed directly to Runtime.exec
        Runtime.getRuntime().exec("ls " + input);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("SecurePipe Java sample app");
    }
}
