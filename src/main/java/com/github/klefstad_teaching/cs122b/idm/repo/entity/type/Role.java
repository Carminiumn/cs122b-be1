package com.github.klefstad_teaching.cs122b.idm.repo.entity.type;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Role
{
    ADMIN(1, "Admin", "Role for admin access", 5),
    EMPLOYEE(2, "Employee", "Role for internal employees", 10),
    PREMIUM(3, "Premium", "Role for premium users", 15);

    private final int    id;
    private final String name;
    private final String description;
    private final int    precedence;

    Role(int id, String name, String description, int precedence)
    {
        this.id = id;
        this.name = name;
        this.description = description;
        this.precedence = precedence;
    }

    public int getId() { return id; }

    @JsonValue public String getName() { return name; }

    @JsonCreator
    public static Role creator(String name)
    {
        for (Role type : values()) {
            if (type.name.equals(name)) {
                return type;
            }
        }

        throw new IllegalArgumentException("Role not found");
    }

    public String getDescription() { return description; }

    public int getPrecedence() { return precedence; }

    public static Role fromId(int id)
    {
        for (Role type : values()) {
            if (type.id == id) {
                return type;
            }
        }

        throw new IllegalArgumentException("Id not found");
    }
}
