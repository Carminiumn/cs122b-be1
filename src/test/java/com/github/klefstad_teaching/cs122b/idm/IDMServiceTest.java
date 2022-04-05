package com.github.klefstad_teaching.cs122b.idm;

import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.result.Result;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import static org.hamcrest.core.IsNot.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@Sql("/idm-test-data.sql")
@AutoConfigureMockMvc
public class IDMServiceTest
{
    private static final String REGISTER_PATH     = "/register";
    private static final String LOGIN_PATH        = "/login";
    private static final String REFRESH_PATH      = "/refresh";
    private static final String AUTHENTICATE_PATH = "/authenticate";

    private static final JSONObject ADMIN    = makeUser("Admin@example.com",
                                                        "AdminPassWord0");
    private static final JSONObject EMPLOYEE = makeUser("Employee@example.com",
                                                        "EmployeePassWord0");
    private static final JSONObject PREMIUM  = makeUser("Premium@example.com",
                                                        "PremiumPassWord0");

    private static final JSONObject ACTIVE = makeUser("Active@example.com",
                                                      "ActivePassWord0");
    private static final JSONObject LOCKED = makeUser("Locked@example.com",
                                                      "LockedPassWord0");
    private static final JSONObject BANNED = makeUser("Banned@example.com",
                                                      "BannedPassWord0");

    private static final JSONObject LOGIN_MIN_PASS = makeUser("LoginMinPass@example.com",
                                                              "ValidPass0");
    private static final JSONObject LOGIN_MAX_PASS = makeUser("LoginMaxPass@example.com",
                                                              "ValidPass01234567890");

    private static final JSONObject LOGIN_MIN_EMAIL = makeUser("a@a.io",
                                                               "MinEmailPassWord0");
    private static final JSONObject LOGIN_MAX_EMAIL = makeUser("LoginIsRightAtMaxLen@example.com",
                                                               "MaxEmailPassWord0");

    private static final String EXPIRED_TOKEN = "c46fc3c2-9791-44d6-a86e-2922ad655284";
    private static final String REVOKED_TOKEN = "399cd90d-e715-484a-bb4d-a8ff35506ef9";

    private final MockMvc    mockMvc;
    private final JWTManager jwtManager;

    @Autowired
    public IDMServiceTest(MockMvc mockMvc,
                          @Value("${idm.key-file-name}") String keyFileName,
                          @Value("${idm.access-token-expire}") Duration accessTokenExpire,
                          @Value("${idm.max-refresh-token-life-time}") Duration maxRefreshTokenLifeTime,
                          @Value("${idm.refresh-token-expire}") Duration refreshTokenExpire)
    {
        this.mockMvc = mockMvc;
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(keyFileName)
                .accessTokenExpire(accessTokenExpire)
                .maxRefreshTokenLifeTime(maxRefreshTokenLifeTime)
                .refreshTokenExpire(refreshTokenExpire)
                .build();

    }

    private static JSONObject makeUser(String email, String password)
    {
        JSONArray jsonArray = new JSONArray();
        password.chars().forEach(digit -> jsonArray.add(String.valueOf((char) digit)));

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("email", email);
        jsonObject.put("password", jsonArray);

        return jsonObject;
    }

    private ResultMatcher[] isResult(Result result)
    {
        return new ResultMatcher[]{
            status().is(result.status().value()),
            jsonPath("result.code").value(result.code()),
            jsonPath("result.message").value(result.message())
        };
    }

    @Test
    public void applicationLoads()
    {
    }

    // Register Tests

    @Test
    public void registerSuccessMinPassword()
        throws Exception
    {
        JSONObject request = makeUser("RegisterMin@example.com", "ValidPass0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_REGISTERED_SUCCESSFULLY));
    }

    @Test
    public void registerSuccessMaxPassword()
        throws Exception
    {
        JSONObject request = makeUser("RegisterMax@example.com", "ValidPass01234567890");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_REGISTERED_SUCCESSFULLY));
    }

    @Test
    public void registerSuccessMinEmail()
        throws Exception
    {
        JSONObject request = makeUser("b@b.io", "ValidPassWord0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_REGISTERED_SUCCESSFULLY));
    }

    @Test
    public void registerSuccessMaxEmail()
        throws Exception
    {
        JSONObject request = makeUser("EmailIsRightAtMaxLen@example.com", "ValidPassWord0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_REGISTERED_SUCCESSFULLY));
    }

    @Test
    public void registerPasswordTooShort()
        throws Exception
    {
        JSONObject request = makeUser("RegisterFail1@example.com", "TooShort0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS));
    }

    @Test
    public void registerPasswordTooLong()
        throws Exception
    {
        JSONObject request = makeUser("RegisterFail2@example.com", "WayTooLongPassword012");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS));
    }

    @Test
    public void registerPasswordMissingNumber()
        throws Exception
    {
        JSONObject request = makeUser("RegisterFail3@example.com", "NoNumberPassword");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT));
    }

    @Test
    public void registerPasswordMissingUpperCase()
        throws Exception
    {
        JSONObject request = makeUser("RegisterFail4@example.com", "nouppercase0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT));
    }

    @Test
    public void registerPasswordMissingLowerCase()
        throws Exception
    {
        JSONObject request = makeUser("RegisterFail5@example.com", "NOLOWERCASE0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT));
    }

    @Test
    public void registerEmailTooShort()
        throws Exception
    {
        JSONObject request = makeUser("a@a.a", "ValidPassWord0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH));
    }

    @Test
    public void registerEmailTooLong()
        throws Exception
    {
        JSONObject request = makeUser("EmailTooLongToSucceed@example.com", "ValidPassWord0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH));
    }

    @Test
    public void registerEmailNotValid()
        throws Exception
    {
        JSONObject request = makeUser("NotValidEmail", "ValidPassWord0");

        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT));
    }

    @Test
    public void registerAlreadyExists()
        throws Exception
    {
        this.mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                                                .content(ACTIVE.toString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_ALREADY_EXISTS));
    }

    @Test
    public void loginSuccessMinPassword()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(LOGIN_MIN_PASS.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").isNotEmpty());
    }

    @Test
    public void loginSuccessMaxPassword()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(LOGIN_MAX_PASS.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").isNotEmpty());
    }

    @Test
    public void loginSuccessMinEmail()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(LOGIN_MIN_EMAIL.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").isNotEmpty());
    }

    @Test
    public void loginSuccessMaxEmail()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(LOGIN_MAX_EMAIL.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").isNotEmpty());
    }

    @Test
    public void loginPasswordTooShort()
        throws Exception
    {
        JSONObject request = makeUser("LoginFail1@example.com", "TooShort0");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginPasswordTooLong()
        throws Exception
    {
        JSONObject request = makeUser("LoginFail2@example.com", "WayTooLongPassword012");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginPasswordMissingNumber()
        throws Exception
    {
        JSONObject request = makeUser("LoginFail3@example.com", "NoNumberPassword");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginPasswordMissingUpperCase()
        throws Exception
    {
        JSONObject request = makeUser("LoginFail4@example.com", "nouppercase0");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginPasswordMissingLowerCase()
        throws Exception
    {
        JSONObject request = makeUser("LoginFail5@example.com", "NOLOWERCASE0");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginEmailTooShort()
        throws Exception
    {
        JSONObject request = makeUser("a@a.a", "ValidPass01234567890");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginEmailTooLong()
        throws Exception
    {
        JSONObject request = makeUser("EmailTooLongToSucceed@example.com", "ValidPass01234567890");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginEmailNotValid()
        throws Exception
    {
        JSONObject request = makeUser("NotValidEmail", "ValidPass01234567890");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginDoesntExist()
        throws Exception
    {
        JSONObject request = makeUser("DoesntExist@example.com", "ValidPass0");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_NOT_FOUND))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginBannedAccount()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(BANNED.toString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_IS_BANNED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginLockedAccount()
        throws Exception
    {
        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(LOCKED.toString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.USER_IS_LOCKED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void loginWrongPassword()
        throws Exception
    {
        JSONObject request = makeUser(ACTIVE.getAsString("email"), "WrongPass0");

        this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                             .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.INVALID_CREDENTIALS))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshActiveToken()
        throws Exception
    {
        JSONObject responseObject =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        String refreshToken = responseObject.getAsString("refreshToken");

        JSONObject request = new JSONObject();
        request.put("refreshToken", responseObject.getAsString("refreshToken"));

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN))
                    .andExpect(jsonPath("accessToken").hasJsonPath())
                    .andExpect(jsonPath("refreshToken").value(refreshToken));
    }

    @Test
    public void refreshExpiredToken()
        throws Exception
    {
        JSONObject request = new JSONObject();
        request.put("refreshToken", EXPIRED_TOKEN);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_IS_EXPIRED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshRevokedToken()
        throws Exception
    {
        JSONObject request = new JSONObject();
        request.put("refreshToken", REVOKED_TOKEN);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_IS_REVOKED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshBeforeExpire()
        throws Exception
    {
        JSONObject loginResponse =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        Thread.sleep(jwtManager.getRefreshTokenExpire().minus(Duration.ofSeconds(1)).toMillis());

        String refreshToken = loginResponse.getAsString("refreshToken");

        JSONObject request = new JSONObject();
        request.put("refreshToken", refreshToken);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").value(refreshToken));
    }

    @Test
    public void refreshAfterExpire()
        throws Exception
    {
        JSONObject loginResponse =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        Thread.sleep(jwtManager.getRefreshTokenExpire().plus(Duration.ofSeconds(1)).toMillis());

        String refreshToken = loginResponse.getAsString("refreshToken");

        JSONObject request = new JSONObject();
        request.put("refreshToken", refreshToken);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_IS_EXPIRED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshAfterExpireIsExtended()
        throws Exception
    {
        JSONObject loginResponse =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        Thread.sleep(jwtManager.getRefreshTokenExpire().minus(Duration.ofSeconds(1)).toMillis());

        String refreshToken = loginResponse.getAsString("refreshToken");

        JSONObject firstRequest = new JSONObject();
        firstRequest.put("refreshToken", refreshToken);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(firstRequest.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN))
                    .andExpect(jsonPath("refreshToken").value(refreshToken))
                    .andExpect(jsonPath("accessToken").isNotEmpty());

        Thread.sleep(jwtManager.getRefreshTokenExpire().minus(Duration.ofSeconds(1)).toMillis());

        JSONObject secondRequest = new JSONObject();
        secondRequest.put("refreshToken", refreshToken);

        JSONObject refreshResponse =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                                       .content(secondRequest.toJSONString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN))
                            .andExpect(jsonPath("accessToken").isNotEmpty())
                            .andExpect(jsonPath("refreshToken").value(not(refreshToken)))
                            .andReturn()
                            .getResponse()
                            .getContentAsString()
            );

        JSONObject thirdRequest = new JSONObject();
        thirdRequest.put("refreshToken", refreshToken);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(thirdRequest.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_IS_REVOKED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());

        String     newRefreshToken  = refreshResponse.getAsString("refreshToken");

        JSONObject fourthRequest = new JSONObject();
        fourthRequest.put("refreshToken", newRefreshToken);

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(fourthRequest.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN))
                    .andExpect(jsonPath("accessToken").isNotEmpty())
                    .andExpect(jsonPath("refreshToken").value(newRefreshToken));
    }

    @Test
    public void refreshAfterMaxExpire()
        throws Exception
    {
        JSONObject loginResponse =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        JSONObject request = new JSONObject();
        request.put("refreshToken", loginResponse.getAsString("refreshToken"));

        Thread.sleep(jwtManager.getMaxRefreshTokenLifeTime().toMillis());

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_IS_EXPIRED))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshTokenInvalidLength()
        throws Exception
    {
        JSONObject request = new JSONObject();
        request.put("refreshToken", "invalidToken");

        Thread.sleep(jwtManager.getMaxRefreshTokenLifeTime().toMillis());

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    @Test
    public void refreshTokenInvalidFormat()
        throws Exception
    {
        JSONObject request = new JSONObject();
        request.put("refreshToken", UUID.randomUUID().toString().replace("-", "."));

        Thread.sleep(jwtManager.getMaxRefreshTokenLifeTime().toMillis());

        this.mockMvc.perform(post(REFRESH_PATH).contentType(MediaType.APPLICATION_JSON)
                                               .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT))
                    .andExpect(jsonPath("accessToken").doesNotHaveJsonPath())
                    .andExpect(jsonPath("refreshToken").doesNotHaveJsonPath());
    }

    // Authenticate Tests

    @Test
    public void authenticateActiveToken()
        throws Exception
    {
        JSONObject responseObject =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        JSONObject request = new JSONObject();
        request.put("accessToken", responseObject.getAsString("accessToken"));

        this.mockMvc.perform(post(AUTHENTICATE_PATH).contentType(MediaType.APPLICATION_JSON)
                                                    .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.ACCESS_TOKEN_IS_VALID));
    }

    @Test
    public void authenticateExpiredToken()
        throws Exception
    {
        JSONObject response =
            (JSONObject) JSONValue.parse(
                this.mockMvc.perform(post(LOGIN_PATH).contentType(MediaType.APPLICATION_JSON)
                                                     .content(ACTIVE.toString()))
                            .andDo(print())
                            .andExpectAll(isResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY))
                            .andReturn()
                            .getResponse()
                            .getContentAsString());

        Thread.sleep(jwtManager.getAccessTokenExpire().toMillis());

        JSONObject request = new JSONObject();
        request.put("accessToken", response.getAsString("accessToken"));

        this.mockMvc.perform(post(AUTHENTICATE_PATH).contentType(MediaType.APPLICATION_JSON)
                                                    .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.ACCESS_TOKEN_IS_EXPIRED));
    }

    @Test
    public void authenticateInvalidTokenKey()
        throws Exception
    {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_521)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .generate();

        JWSSigner signer = new ECDSASigner(ecJWK);

        SignedJWT jws = new SignedJWT(
            new JWSHeader(JWSAlgorithm.ES512),
            new JWTClaimsSet.Builder()
                .subject("Subject")
                .expirationTime(Date.from(Instant.now().plus(Duration.ofHours(1))))
                .claim("roles", new ArrayList<String>())
                .build());

        jws.sign(signer);

        JSONObject request = new JSONObject();
        request.put("accessToken", jws.serialize());

        this.mockMvc.perform(post(AUTHENTICATE_PATH).contentType(MediaType.APPLICATION_JSON)
                                                    .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.ACCESS_TOKEN_IS_INVALID));
    }

    @Test
    public void authenticateInvalidClaims()
        throws Exception
    {
        JWTClaimsSet claimsSet =
            new JWTClaimsSet.Builder()
                .subject("Email")
                .expirationTime(Date.from(Instant.now().plus(Duration.ofHours(1))))
                .build();

        JWSHeader header =
            new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                .keyID(jwtManager.getEcKey().getKeyID())
                .type(JWTManager.JWS_TYPE)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());

        JSONObject request = new JSONObject();
        request.put("accessToken", signedJWT.serialize());

        this.mockMvc.perform(post(AUTHENTICATE_PATH).contentType(MediaType.APPLICATION_JSON)
                                                    .content(request.toJSONString()))
                    .andDo(print())
                    .andExpectAll(isResult(IDMResults.ACCESS_TOKEN_IS_INVALID));
    }
}
