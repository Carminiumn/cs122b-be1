package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;

    @Autowired
    public IDMAuthenticationManager(IDMRepo repo)
    {
        this.repo = repo;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public User selectAndAuthenticateUser(String email, char[] password)
    {
        return null;
    }

    public void createAndInsertUser(String email, char[] password)
    {
    }

    public void insertRefreshToken(RefreshToken refreshToken)
    {
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        return null;
    }

    public void updateRefreshTokenExpireTime(RefreshToken token)
    {
    }

    public void expireRefreshToken(RefreshToken token)
    {
    }

    public void revokeRefreshToken(RefreshToken token)
    {
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        return null;
    }
}
