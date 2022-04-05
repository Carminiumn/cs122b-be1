package com.github.klefstad_teaching.cs122b.idm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.time.Duration;
import java.util.Objects;

@ConstructorBinding
@ConfigurationProperties(prefix = "idm")
public class IDMServiceConfig
{
    private final String   keyFileName;
    private final Duration accessTokenExpire;
    private final Duration refreshTokenExpire;
    private final Duration maxRefreshTokenLifeTime;

    public IDMServiceConfig(String keyFileName,
                            Duration accessTokenExpire,
                            Duration refreshTokenExpire,
                            Duration maxRefreshTokenLifeTime)
    {
        this.keyFileName = Objects.requireNonNull(keyFileName);
        this.accessTokenExpire = Objects.requireNonNull(accessTokenExpire);
        this.refreshTokenExpire = Objects.requireNonNull(refreshTokenExpire);
        this.maxRefreshTokenLifeTime = Objects.requireNonNull(maxRefreshTokenLifeTime);
    }

    public String keyFileName()
    {
        return keyFileName;
    }

    public Duration accessTokenExpire()
    {
        return accessTokenExpire;
    }

    public Duration refreshTokenExpire()
    {
        return refreshTokenExpire;
    }

    public Duration maxRefreshTokenLifeTime()
    {
        return maxRefreshTokenLifeTime;
    }
}
