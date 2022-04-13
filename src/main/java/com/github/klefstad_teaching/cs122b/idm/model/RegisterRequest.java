package com.github.klefstad_teaching.cs122b.idm.model;

public class RegisterRequest {
    private String email;
    private char[] password;

    public String getEmail() {
        return email;
    }

    public RegisterRequest setEmail(String email) {
        this.email = email;
        return this;
    }

    public char[] getPassword() {
        return password;
    }

    public RegisterRequest setPassword(char[] password) {
        this.password = password;
        return this;
    }
}
