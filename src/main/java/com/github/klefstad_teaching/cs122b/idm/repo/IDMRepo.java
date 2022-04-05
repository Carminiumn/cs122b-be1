package com.github.klefstad_teaching.cs122b.idm.repo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class IDMRepo
{

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
    }
}
