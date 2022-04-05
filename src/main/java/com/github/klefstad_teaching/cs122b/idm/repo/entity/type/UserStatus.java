package com.github.klefstad_teaching.cs122b.idm.repo.entity.type;

import com.fasterxml.jackson.annotation.JsonValue;

public enum UserStatus
{
    ACTIVE(1, "Active"),
    LOCKED(2, "Locked"),
    BANNED(3, "Banned");

    private final int    id;
    private final String value;

    UserStatus(int id, String value)
    {
        this.id = id;
        this.value = value;
    }

    public int id() { return id; }

    @JsonValue public String value() { return value; }

    public static UserStatus fromId(int id)
    {
        for (UserStatus type : values()) {
            if (type.id == id) {
                return type;
            }
        }

        throw new IllegalArgumentException("Id not found");
    }
}
