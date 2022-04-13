package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
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
        JWSHeader header =
                new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                    .keyID(jwtManager.getEcKey().getKeyID())
                    .type(JWTManager.JWS_TYPE).build();

        SignedJWT jwt = new SignedJWT(header, claimsSet);
        jwt.sign(jwtManager.getSigner());
        return jwt;
    }

    private void verifyJWT(SignedJWT jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt.serialize());

            signedJWT.verify(jwtManager.getVerifier());
            jwtManager.getJwtProcessor().process(signedJWT, null);

            // Do logic to check if expired manually
            signedJWT.getJWTClaimsSet().getExpirationTime();
        }
        catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
            e.printStackTrace();
        }
    }

    public String buildAccessToken(User user)
    {
        Instant now = Instant.now();
        Instant expireTime = now.plus(jwtManager.getAccessTokenExpire());
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                    .subject(user.getEmail())
                    .expirationTime(Date.from(expireTime))
                    .issueTime(Date.from(now))
                    .claim(JWTManager.CLAIM_ID, user.getId())
                    .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                    .build();

        try {
            SignedJWT signed = buildAndSignJWT(claimsSet);
            return signed.serialize();

        }
        catch (JOSEException e) {
            e.printStackTrace();
        }

        return null;
    }

    public void verifyAccessToken(String jws)
            throws ParseException, JOSEException, BadJOSEException, IllegalStateException {
        SignedJWT signed = SignedJWT.parse(jws);
        signed.verify(jwtManager.getVerifier());
        jwtManager.getJwtProcessor().process(signed, null);

        if (Instant.now().isAfter(signed.getJWTClaimsSet()
                .getExpirationTime().toInstant())) {
            throw new IllegalStateException();
        }
    }

    public RefreshToken buildRefreshToken(User user)
    {
        return new RefreshToken()
                .setToken(generateUUID().toString())
                .setUserId(user.getId())
                .setExpireTime(
                        Instant.now().plus(jwtManager.getRefreshTokenExpire())
                )
                .setMaxLifeTime(
                        Instant.now().plus(jwtManager.getMaxRefreshTokenLifeTime())
                );
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        return Instant.now().isAfter(refreshToken.getExpireTime());
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return Instant.now().isAfter(refreshToken.getMaxLifeTime());
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {
        refreshToken.setExpireTime(
                Instant.now().plus(jwtManager.getRefreshTokenExpire())
        );
    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
