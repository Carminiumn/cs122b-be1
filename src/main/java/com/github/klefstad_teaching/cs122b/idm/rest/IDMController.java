package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.result.Result;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.*;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

@RestController
public class IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;

    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }

    @PostMapping("/register")
    public void register(@RequestBody RegisterRequest request) {
        // basic validation
        validateCredentials(request.getEmail(), request.getPassword());

        // query for email to see if exists, then throw error
        try {
            String check_email = authManager.repo.getTemplate().queryForObject(
                    "SELECT email FROM idm.user WHERE email = :email",
                    Collections.singletonMap("email", request.getEmail()),
                    String.class
            );
            if (check_email != null) {
                throw new ResultError(IDMResults.USER_ALREADY_EXISTS);
            }
        }
        catch (EmptyResultDataAccessException e) {
            // at this point we know for sure that the email doesn't exist
            authManager.createAndInsertUser(request.getEmail(), request.getPassword());
            throw new ResultError(IDMResults.USER_REGISTERED_SUCCESSFULLY);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        // formatting
        validateCredentials(request.getEmail(), request.getPassword());

        // check if user exists
        try {
            authManager.repo.getTemplate().queryForObject(
                    "SELECT email FROM idm.user WHERE email = :email",
                    Collections.singletonMap("email", request.getEmail()),
                    String.class
            );
        }
        catch (EmptyResultDataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }

        // check password
        User user = authManager.selectAndAuthenticateUser(
                request.getEmail(), request.getPassword()
        );

        if (user == null) {
            throw new ResultError(IDMResults.INVALID_CREDENTIALS);
        }

        if (user.getUserStatus().value().equals("Locked")) {
            throw new ResultError(IDMResults.USER_IS_LOCKED);
        }

        if (user.getUserStatus().value().equals("Banned")) {
            throw new ResultError(IDMResults.USER_IS_BANNED);
        }

        return ResponseEntity.status(HttpStatus.OK)
                .body(new LoginResponse()
                        .setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY)
                        .setAccessToken(jwtManager.buildAccessToken(user))
                        .setRefreshToken(jwtManager.buildRefreshToken(user).getToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestBody RefreshRequest request) {
        if (request.getRefreshToken().length() != 36) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH);
        }

        try {
            UUID.fromString(request.getRefreshToken());
        }
        catch (IllegalArgumentException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT);
        }

        try {
            authManager.repo.getTemplate().queryForObject(
                    "SELECT token FROM idm.refresh_token where token = :refreshToken",
                    Collections.singletonMap("refreshToken", request.getRefreshToken()),
                    String.class
            );
        }
        catch (EmptyResultDataAccessException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);
        }

        return ResponseEntity.status(HttpStatus.OK)
                .body(new RefreshResponse()
                        .setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN)
                        .setRefreshToken(request.getRefreshToken()));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateResponse> authenticate(
            @RequestBody AuthenticateRequest request) {
        try {
            jwtManager.verifyAccessToken(request.getAccessToken());
        }
        catch (ParseException | JOSEException | BadJOSEException e) {
            throw new ResultError(IDMResults.ACCESS_TOKEN_IS_INVALID);
        }
        catch (IllegalStateException e) {
            throw new ResultError(IDMResults.ACCESS_TOKEN_IS_EXPIRED);
        }

        throw new ResultError(IDMResults.ACCESS_TOKEN_IS_VALID);
    }

    public void validateCredentials(String email, char[] password) {
        String pw = new String(password);
        if (email.length() < 6 || email.length() > 32) {
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
        }

        if (pw.length() < 10 || pw.length() > 20) {
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        if (!email.matches("^[A-Za-z0-9]+@[A-Za-z0-9]+.[A-Za-z0-9]+$")) {
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        if (!pw.matches("^(?=.*[0-9])(?=.*[A-Z])(?=.*[a-z])[A-Za-z0-9]+$")) {
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        }
    }
}
