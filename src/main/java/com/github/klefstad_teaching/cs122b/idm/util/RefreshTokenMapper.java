package com.github.klefstad_teaching.cs122b.idm.util;

import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class RefreshTokenMapper implements RowMapper<RefreshToken> {
    @Override
    public RefreshToken mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new RefreshToken()
                .setId(rs.getInt("id"))
                .setToken(rs.getString("token"))
                .setUserId(rs.getInt("user_id"))
                .setTokenStatus(
                        TokenStatus.fromId( rs.getInt("token_status_id"))
                )
                .setExpireTime(rs.getTimestamp("expire_time").toInstant())
                .setMaxLifeTime(rs.getTimestamp("max_life_time").toInstant());
    }
}
