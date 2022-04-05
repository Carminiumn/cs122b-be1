package com.github.klefstad_teaching.cs122b.idm.repo.entity.type;

import com.fasterxml.jackson.annotation.JsonValue;

public enum TokenStatus
{
    ACTIVE(1, "Active"),
    EXPIRED(2, "Expired"),
    REVOKED(3, "Revoked");

    private final int    id;
    private final String value;

    TokenStatus(int id, String value)
    {
        this.id = id;
        this.value = value;
    }

    public int id() { return id; }

    @JsonValue public String value() { return value; }

    public static TokenStatus fromId(int id)
    {
        for (TokenStatus type : values()) {
            if (type.id == id) {
                return type;
            }
        }

        throw new IllegalArgumentException("Id not found");
    }
}
