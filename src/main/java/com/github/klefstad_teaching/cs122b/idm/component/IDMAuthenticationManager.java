package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.util.RefreshTokenMapper;
import com.github.klefstad_teaching.cs122b.idm.util.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Ref;
import java.sql.Time;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

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
        try {
            String sql = "SELECT * FROM idm.user WHERE email = :email;";

            MapSqlParameterSource source = new MapSqlParameterSource()
                    .addValue("email", email, Types.VARCHAR);

            // should throw DataAccessException if doesn't exist
            User user = repo.getTemplate().query(sql, source, new UserMapper()).get(0);

            String hashedPwGuess = Base64.getEncoder()
                    .encodeToString(hashPassword(password, user.getSalt()));

            if (hashedPwGuess.equals(user.getHashedPassword())) {
                return user;
            }
        }
        catch (DataAccessException e) {
            e.printStackTrace();
        }

        return null;
    }

    public void createAndInsertUser(String email, char[] password)
    {
        byte[] salt = genSalt();
        String base64Salt = Base64.getEncoder().encodeToString(salt);
        byte[] hashed_pw = hashPassword(password, salt);
        int user_id = 1;

        MapSqlParameterSource source = new MapSqlParameterSource()
                .addValue("email", email, Types.VARCHAR)
                .addValue("user_id", user_id, Types.INTEGER)
                .addValue("base64Salt", base64Salt, Types.CHAR)
                .addValue("hashed_pw", hashed_pw, Types.CHAR);

        repo.getTemplate().update(
                "INSERT INTO idm.user(email, user_status_id, salt, hashed_password) " +
                "VALUES (:email, :user_id, :base64Salt, :hashed_pw);", source);
    }

    public void insertRefreshToken(RefreshToken refreshToken)
    {
        MapSqlParameterSource source = new MapSqlParameterSource()
                .addValue("token", refreshToken.getToken(), Types.VARCHAR)
                .addValue("user_id", refreshToken.getUserId(), Types.INTEGER)
                .addValue("token_status_id",
                        refreshToken.getTokenStatus().id(),
                        Types.INTEGER)
                .addValue("expire_time",
                        Timestamp.from(refreshToken.getExpireTime()),
                        Types.TIMESTAMP)
                .addValue("max_life_time",
                        Timestamp.from(refreshToken.getMaxLifeTime()),
                        Types.TIMESTAMP);

        repo.getTemplate().update(
                "INSERT INTO idm.refresh_token" +
                "(token, user_id, token_status_id, expire_time, max_life_time) " +
                "VALUES " +
                "(:token, :user_id, :token_status_id, :expire_time, :max_life_time);",
                source
        );
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        try {
            String sql = "SELECT * FROM idm.refresh_token WHERE token = :token;";

            MapSqlParameterSource source = new MapSqlParameterSource()
                    .addValue("token", token, Types.VARCHAR);

            RefreshToken newToken = repo.getTemplate().query(
                    sql, source, new RefreshTokenMapper()
            ).get(0);

            if (token.equals(newToken.getToken())) {
                return newToken;
            }
        }
        catch (DataAccessException e) {
            e.printStackTrace();
        }
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
