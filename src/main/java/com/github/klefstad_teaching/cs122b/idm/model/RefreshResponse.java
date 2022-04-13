package com.github.klefstad_teaching.cs122b.idm.model;

import com.github.klefstad_teaching.cs122b.core.result.Result;

public class RefreshResponse {
    private Result result;
    private String accessToken, refreshToken;

    public Result getResult() {
        return result;
    }

    public RefreshResponse setResult(Result result) {
        this.result = result;
        return this;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public RefreshResponse setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public RefreshResponse setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
        return this;
    }
}
