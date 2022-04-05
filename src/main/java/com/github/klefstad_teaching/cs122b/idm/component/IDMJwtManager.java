package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();
    }

    private SignedJWT buildAndSignJWT(JWTClaimsSet claimsSet)
        throws JOSEException
    {
        return null;
    }

    private void verifyJWT(SignedJWT jwt)
        throws JOSEException, BadJOSEException
    {

    }

    public String buildAccessToken(User user)
    {
        return null;
    }

    public void verifyAccessToken(String jws)
    {

    }

    public RefreshToken buildRefreshToken(User user)
    {
        return null;
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        return false;
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {

    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
