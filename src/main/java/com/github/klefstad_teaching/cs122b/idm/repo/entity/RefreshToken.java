package com.github.klefstad_teaching.cs122b.idm.repo.entity;

import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

public class RefreshToken
{
    private Integer     id;
    private String      token;
    private Integer     userId;
    private TokenStatus tokenStatus;
    private Instant     expireTime;
    private Instant     maxLifeTime;

    public Integer getId()
    {
        return id;
    }

    public RefreshToken setId(Integer id)
    {
        this.id = id;
        return this;
    }

    public String getToken()
    {
        return token;
    }

    public RefreshToken setToken(String token)
    {
        this.token = token;
        return this;
    }

    public Integer getUserId()
    {
        return userId;
    }

    public RefreshToken setUserId(Integer userId)
    {
        this.userId = userId;
        return this;
    }

    public TokenStatus getTokenStatus()
    {
        return tokenStatus;
    }

    public RefreshToken setTokenStatus(TokenStatus tokenStatus)
    {
        this.tokenStatus = tokenStatus;
        return this;
    }

    public Instant getExpireTime()
    {
        return expireTime;
    }

    public RefreshToken setExpireTime(Instant expireTime)
    {
        this.expireTime = expireTime;
        return this;
    }

    public Instant getMaxLifeTime()
    {
        return maxLifeTime;
    }

    public RefreshToken setMaxLifeTime(Instant maxLifeTime)
    {
        this.maxLifeTime = maxLifeTime;
        return this;
    }
}
