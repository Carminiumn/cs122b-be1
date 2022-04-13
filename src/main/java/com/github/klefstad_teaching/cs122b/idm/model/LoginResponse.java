package com.github.klefstad_teaching.cs122b.idm.model;

import com.github.klefstad_teaching.cs122b.core.result.Result;

public class LoginResponse {
    private Result result;
    private String accessToken, refreshToken;

    public Result getResult() {
        return result;
    }

    public LoginResponse setResult(Result result) {
        this.result = result;
        return this;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public LoginResponse setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public LoginResponse setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }
}
