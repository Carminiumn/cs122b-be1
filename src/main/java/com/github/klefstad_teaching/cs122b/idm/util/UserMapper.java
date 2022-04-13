package com.github.klefstad_teaching.cs122b.idm.util;

import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class UserMapper implements RowMapper<User> {
    @Override
    public User mapRow(ResultSet rs, int rowNum) throws SQLException {
        return new User()
                .setId(rs.getInt("id"))
                .setEmail(rs.getString("email"))
                .setUserStatus(
                        UserStatus.fromId(
                        rs.getInt("user_status_id"))
                )
                .setSalt(rs.getString("salt"))
                .setHashedPassword(rs.getString("hashed_password"));
    }
}
