package com.github.klefstad_teaching.cs122b.idm.model;

public class LoginRequest {
    private String email;
    private char[] password;

    public String getEmail() {
        return email;
    }

    public LoginRequest setEmail(String email) {
        this.email = email;
        return this;
    }

    public char[] getPassword() {
        return password;
    }

    public LoginRequest setPassword(char[] password) {
        this.password = password;
        return this;
    }
}
