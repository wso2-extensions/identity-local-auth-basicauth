/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.basicauth;

import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.recovery.RecoveryScenarios;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.recovery.util.Utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.mockito.Matchers.anyString;

import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SIGNUP;
/**
 * Unit test cases for the Basic Authenticator.
 */
@PrepareForTest({IdentityTenantUtil.class, BasicAuthenticatorServiceComponent.class, User
        .class, MultitenantUtils.class, FrameworkUtils.class, FileBasedConfigurationBuilder.class,
        IdentityUtil.class, UserCoreUtil.class, Utils.class, SignatureUtil.class, BasicAuthenticatorDataHolder.class})
public class BasicAuthenticatorTestCase extends PowerMockIdentityBaseTest {

    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;
    private AuthenticationContext mockAuthnCtxt;
    private RealmService mockRealmService;
    private UserRealm mockRealm;
    private UserStoreManager mockUserStoreManager;
    private FileBasedConfigurationBuilder mockFileBasedConfigurationBuilder;
    private IdentityErrorMsgContext mockIdentityErrorMsgContext;
    private User mockUser;
    private IdentityGovernanceService governanceService;

    private AuthenticatedUser authenticatedUser;
    private Boolean isrememberMe = false;
    private Boolean isUserTenantDomainMismatch = true;
    private String redirect;

    private String dummyUserName = "dummyUserName";
    private String dummyQueryParam = "dummyQueryParams";
    private String dummyLoginPage = "dummyLoginPageurl";
    private String dummyPassword = "dummyPassword";
    private int dummyTenantId = -1234;
    private String dummyVal = "dummyVal";
    private String dummyDomainName = "dummyDomain";
    private String dummyRetryURL = "DummyRetryUrl";
    private String dummyEncodedVal = "DummyRetryUrl?dummyQueryParams";
    private String callback = dummyLoginPage + "?" + dummyQueryParam + "&authenticators=BasicAuthenticator";

    private String defaultCaptchaConfigName = "sso.login.recaptcha" +
            CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;

    private BasicAuthenticator basicAuthenticator;

    @BeforeTest
    public void setup() throws IdentityGovernanceException {

        basicAuthenticator = new BasicAuthenticator();

        System.setProperty("carbon.config.dir.path", "carbon.home");

        governanceService = mock(IdentityGovernanceService.class);

        Property[] captchaProperties = new Property[1];
        Property captchaEnabled = new Property();
        captchaEnabled.setDefaultValue("false");
        captchaProperties[0] = captchaEnabled;

        when(governanceService.getConfiguration(any(String[].class), anyString())).thenReturn(captchaProperties);

        BasicAuthenticatorDataHolder.getInstance().setIdentityGovernanceService(governanceService);
    }

    @DataProvider(name = "UsernameAndPasswordProvider")
    public Object[][] getWrongUsernameAndPassword() {

        return new String[][]{
                {"admin", null, "false"},
                {null, "admin", "false"},
                {null, null, "false"},
                {"admin", "admin", "true"},
                {"", "", "true"}
        };
    }

    @Test(dataProvider = "UsernameAndPasswordProvider")
    public void canHandleTestCase(String userName, String password, String expected) {

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(userName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(password);
        assertEquals(Boolean.valueOf(expected).booleanValue(), basicAuthenticator.canHandle(mockRequest),
                "Invalid can handle response for the request.");
    }

    @Test
    public void processSuccessTestCase() throws Exception {

        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.isLogoutRequest()).thenReturn(true);
        assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void processAutoLoginCookieSuccessTestCase() throws Exception {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put("UserNameAttributeClaimUri", "http://wso2.org/claims/username");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("BasicAuthenticator", true,
                parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockAuthnCtxt = mock(AuthenticationContext.class);

        when(mockAuthnCtxt.isLogoutRequest()).thenReturn(false);
        when(mockAuthnCtxt.getTenantDomain()).thenReturn(dummyDomainName);
        when(mockRequest.getParameter("username")).thenReturn("admin");

        mockStatic(Utils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockStatic(FrameworkUtils.class);
        mockStatic(SignatureUtil.class);

        when(SignatureUtil.validateSignature("admin", Base64.getDecoder().decode("cY6Vs5oBbH0xqjtkDFObZR5u" +
                "y1xZhBUtPyFw4V7UpNbiZ0M6Xnl5BXqEw0Q6Vqx1UJRzMPZ7VMdNjBvqRyxA6kSqCQzkbRPHY0lGhKiksfkRKug9CiSa7BAyjE" +
                "hmnqbWaGzppnqYqAly8dVgaf5xZxFdai17cbCxdE+suT/noKpc02lJki6HzXpwj2i144qiG6HLa3B6a+2HE05mqi8zi9CCi" +
                "UASWp96Go2o81EqqVTWF+JoGs9AK0ZMR+YuJQf+nyZn5xyRbewHP7P/0aRc6mePsH3b2VZAcExZv7Up530oFmzlHLwGQESNCwG" +
                "34I+KMG9DhS2GHEKf3Ovi4B83UQ=="))).thenReturn(true);
        when(FrameworkUtils.prependUserStoreDomainToName("admin")).thenReturn("admin" + "@"
                + dummyDomainName);
        when(Utils.getConnectorConfig("Recovery.AutoLogin.Enable", dummyDomainName)).thenReturn("true");
        when(IdentityTenantUtil.getTenantIdOfUser("admin" + "@" + dummyDomainName)).thenReturn(dummyTenantId);
        when(UserCoreUtil.getDomainFromThreadLocal()).thenReturn(dummyDomainName);

        mockRealmService = mock(RealmService.class);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);

        RealmConfiguration mockRealmConfiguration = mock(RealmConfiguration.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantUserRealm(dummyTenantId)).thenReturn(mockRealm);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId))
                .thenReturn(mockRealm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getSecondaryUserStoreManager(dummyDomainName)).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty("MultipleAttributeEnable")).thenReturn("false");
        when(MultitenantUtils.getTenantDomain("admin" + "@" + dummyDomainName)).thenReturn(dummyDomainName);

        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie("ALOR", "eyJzaWduYXR1cmUiOiJjWTZWczVvQmJIMHhxanRrREZPYlpSNXV5MXhaaEJVdFB5R" +
                "nc0VjdVcE5iaVowTTZYbmw1QlhxRXcwUTZWcXgxVUpSek1QWjdWTWROakJ2cVJ5eEE2a1NxQ1F6a2JSUEhZMGxHaEtpa3Nma1J" +
                "LdWc5Q2lTYTdCQXlqRWhtbnFiV2FHenBwbnFZcUFseThkVmdhZjV4WnhGZGFpMTdjYkN4ZEUrc3VUXC9ub0twYzAybEpraTZ" +
                "Ielhwd2oyaTE0NHFpRzZITGEzQjZhKzJIRTA1bXFpOHppOUNDaVVBU1dwOTZHbzJvODFFcXFWVFdGK0pvR3M5QUswWk1SK1l1" +
                "SlFmK255Wm41eHlSYmV3SFA3UFwvMGFSYzZtZVBzSDNiMlZaQWNFeFp2N1VwNTMwb0ZtemxITHdHUUVTTkN3RzM0SStLTUc5R" +
                "GhTMkdIRUtmM092aTRCODNVUT09IiwidXNlcm5hbWUiOiJhZG1pbiJ9");
        when(mockRequest.getCookies()).thenReturn(cookies);

        assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void processAutoLoginNewCookieSuccessTestCase() throws Exception {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put("UserNameAttributeClaimUri", "http://wso2.org/claims/username");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("BasicAuthenticator", true,
                parameterMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockAuthnCtxt = mock(AuthenticationContext.class);

        when(mockAuthnCtxt.isLogoutRequest()).thenReturn(false);
        when(mockAuthnCtxt.getTenantDomain()).thenReturn(dummyDomainName);
        when(mockRequest.getParameter("username")).thenReturn("admin");

        mockStatic(Utils.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(UserCoreUtil.class);
        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockStatic(FrameworkUtils.class);
        mockStatic(SignatureUtil.class);

        JSONObject cookieValue = new JSONObject();
        cookieValue.put("username", "admin");
        cookieValue.put("flowType", SIGNUP);
        String content = cookieValue.toString();
        JSONObject cookieValueInJson = new JSONObject();
        cookieValueInJson.put("content", content);
        cookieValueInJson.put("signature", "eyJzaWduYXR1cmUiOiJBeTRTU1h1bXlhWFpzYzBnS0J1SjdUQzgyNzEzb1BiWlRjSDZs" +
                "XFxcL29XcE1vaVNJVUFHcWwyb2tWOGZ0c3VPMWlrdUZQaUE1Qm1LNFFpdzNpakVTaXdmbFBzcmdNTVVFdEcrMnE3cEQya09oc0p" +
                "1NmVuRnQ5Qlc5THl0YjlsSmlmV0hJZXVGRDllckFyUDhiWExocTE1WFFmSnVGSlNtVnBIZTZub0RrNnVIY2ZLTW5aVmF2d0xza2" +
                "5DZE5mYnZXQitxUkF3dnJBSmtLTG9vZVZpM2t4RlBHbmcwaFlRbnNKeHJcXFwvOTNwVnpmN1xcXC9PcmZhcFU2bzJXNEZvdk01d" +
                "XJ6SjhDWmVkakpHZm5qdjV5bXNjRlN3U1NWVDljZnhISVVBWDFaQU9CZzRSMVZXNnhlbm9wcjYzTkFIYXZINFNESSs0UFl2Y1Ju" +
                "S0J1dVR5YTB0dm0rdTVUaVE9PSIsImNvbnRlbnQiOiJ7XCJ1c2VybmFtZVwiOlwiYWRtaW5cIixcImZsb3dUeXBlXCI6XCJTSUdO" +
                "VVBcIn0ifQ==");

        when(SignatureUtil.validateSignature(any(byte[].class), anyString(), any(byte[].class))).thenReturn(true);
        when(SignatureUtil.getThumbPrintForAlias("alias")).thenReturn(new byte[0]);
        when(FrameworkUtils.prependUserStoreDomainToName("admin")).thenReturn("admin" + "@"
                + dummyDomainName);
        when(Utils.getConnectorConfig(SELF_REGISTRATION_AUTO_LOGIN, dummyDomainName)).thenReturn("true");
        when(Utils.getConnectorConfig(SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME, dummyDomainName)).thenReturn("alias");
        when(IdentityTenantUtil.getTenantIdOfUser("admin" + "@" + dummyDomainName)).thenReturn(dummyTenantId);
        when(UserCoreUtil.getDomainFromThreadLocal()).thenReturn(dummyDomainName);

        mockRealmService = mock(RealmService.class);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);

        RealmConfiguration mockRealmConfiguration = mock(RealmConfiguration.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantUserRealm(dummyTenantId)).thenReturn(mockRealm);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId))
                .thenReturn(mockRealm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getSecondaryUserStoreManager(dummyDomainName)).thenReturn(mockUserStoreManager);
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty("MultipleAttributeEnable")).thenReturn("false");
        when(MultitenantUtils.getTenantDomain("admin" + "@" + dummyDomainName)).thenReturn(dummyDomainName);

        Cookie[] cookies = new Cookie[1];
        cookies[0] = new Cookie("ALOR",
                Base64.getEncoder().encodeToString(cookieValueInJson.toString().getBytes()));
        when(mockRequest.getCookies()).thenReturn(cookies);

        assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }
    @Test
    public void isEnableSelfRegistrationAutoLoginTest() throws AuthenticationFailedException, IdentityEventException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockStatic(Utils.class);
        when(Utils.getConnectorConfig("SelfRegistration.AutoLogin.Enable", dummyDomainName)).thenReturn("true");
        when(mockAuthnCtxt.getTenantDomain()).thenReturn(dummyDomainName);
        assertEquals(basicAuthenticator.isEnableSelfRegistrationAutoLogin(mockAuthnCtxt), true);
    }

    @DataProvider(name = "SelfRegistrationAutoLoginDataProvider")
    public Object[][] getSelfRegistrationAutoLogin() {

        return new String[][] {
                {null, "Error occurred while resolving isEnableSelfRegistrationAutoLogin property."},
        };
    }

    @Test(dataProvider = "SelfRegistrationAutoLoginDataProvider")
    public void isEnableSelfRegistrationAutoLoginExceptionTest(String tenant, Object expected ) throws

            IdentityEventException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockStatic(Utils.class);
        when(mockAuthnCtxt.getTenantDomain()).thenReturn(tenant);
        when(Utils.getConnectorConfig("SelfRegistration.AutoLogin.Enable", tenant)).
                thenThrow(new IdentityEventException("Error"));
        try {
            basicAuthenticator.isEnableSelfRegistrationAutoLogin(mockAuthnCtxt);
        } catch (Exception e) {
            assertEquals(e.getMessage(),expected);
        }
    }

    @DataProvider(name = "SelfRegistrationAutoLoginAliasDataProvider")
    public Object[][] getSelfRegistrationAutoLoginAlias() {

        return new String[][] {
                {null, "Error occurred while resolving SelfRegistration.AutoLogin.AliasName property."},
        };
    }

    @Test(dataProvider = "SelfRegistrationAutoLoginAliasDataProvider")
    public void getSelfRegistrationAutoLoginAliasExceptionTest(String tenant, Object expected ) throws
            IdentityEventException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockStatic(Utils.class);
        when(mockAuthnCtxt.getTenantDomain()).thenReturn(tenant);
        when(Utils.getConnectorConfig("SelfRegistration.AutoLogin.AliasName", tenant)).
                thenThrow(new IdentityEventException("Error"));
        try {
            basicAuthenticator.getSelfRegistrationAutoLoginAlias(mockAuthnCtxt);
        } catch (Exception e) {
            assertEquals(e.getMessage(),expected);
        }
    }
    @Test
    public void processIncompleteTestCase() throws IOException, AuthenticationFailedException, LogoutFailedException {

        initiateAuthenticationRequest();
        when(mockAuthnCtxt.isLogoutRequest()).thenReturn(false);
        assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test
    public void getFriendlyNameTestCase() {

        assertEquals(basicAuthenticator.getFriendlyName(), BasicAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME);
    }

    @Test
    public void getNameTestCase() {

        assertEquals(basicAuthenticator.getName(), BasicAuthenticatorConstants.AUTHENTICATOR_NAME);
    }

    @Test
    public void retryAuthenticationEnabledTestCase() {

        assertTrue(basicAuthenticator.retryAuthenticationEnabled());
    }

    @Test
    public void getContextIdentifierTestCase() {

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter("sessionDataKey")).thenReturn(dummyVal);
        assertEquals(basicAuthenticator.getContextIdentifier(mockRequest), dummyVal);
    }

    @DataProvider(name = "realmProvider")
    public Object[][] getRealm() {

        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);

        return new Object[][]{
                {null, "Cannot find the user realm for the given tenant: " + dummyTenantId, null, null},
                {mockRealm, "User authentication failed due to invalid credentials", dummyVal, null},
                {mockRealm, "User authentication failed due to invalid credentials", null, null},
                {mockRealm, "Credential mismatch.", null, new HashMap<String, String>() {{
                    put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, "dummyUsername2");
                }}},
        };
    }

    @Test(dataProvider = "realmProvider")
    public void processAuthenticationResponseTestCaseForException(Object realm, Object expected, Object
            recapchaUserDomain, Object authenticatorParams) throws Exception {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.getProperties()).thenReturn(new HashMap<String, Object>());
        when(mockAuthnCtxt.getAuthenticatorParams("common"))
                .thenReturn((Map<String, String>) authenticatorParams);

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(dummyPassword);

        mockResponse = mock(HttpServletResponse.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(dummyTenantId);

        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockRealmService = mock(RealmService.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId)).thenReturn((UserRealm) realm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(dummyUserName)).thenReturn(dummyUserName);
        when(mockUserStoreManager.authenticate(
                MultitenantUtils.getTenantAwareUsername(dummyUserName), dummyPassword)).thenReturn(false);

        mockStatic(IdentityUtil.class);
        Map<String, Object> mockedThreadLocalMap = new HashMap<>();
        mockedThreadLocalMap.put("user-domain-recaptcha", recapchaUserDomain);
        IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.preprocessUsername(dummyUserName, mockAuthnCtxt)).thenReturn(dummyUserName);

        mockUser = mock(User.class);
        when(mockUser.getUserName()).thenReturn(dummyUserName);
        mockStatic(User.class);
        when(User.getUserFromUserName(anyString())).thenReturn(mockUser);
        try {
            basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
        } catch (Exception ex) {
            assertEquals(ex.getMessage(), expected);
        }
    }

    @DataProvider(name = "multipleAttributeprovider")
    public Object[][] getMultipleAttributeProvider() {

        String dummyUserNameValue = "dummyusernameValue";
        return new String[][]{
                {null, dummyUserName, null, null, "true", "false"},
                {null, dummyUserName, null, "", "true", "false"},
                {null, dummyUserName, null, dummyUserNameValue, "true", "true"},
                {null, dummyUserName, null, dummyUserNameValue, "true", "false"},
                {null, dummyUserName, null, null, "false", "true"},
                {null, dummyUserName, "off", null, "false", "false"},
                {"", dummyUserName, "off", null, "false", "false"},
                {dummyDomainName, dummyUserName, "off", null, "false", "false"},
                {null, "", "on", null, "false", "false"},
                {null, null, "on", null, "false", "false"}
        };
    }

    @Test(dataProvider = "multipleAttributeprovider")
    public void processAuthenticationResponseTestcaseWithMultiAttribute(String domainName, String userNameUri, String
            chkRemember, String userNameValue, String multipleAttributeEnable, String debugEnabled)
            throws UserStoreException, NoSuchMethodException, InvocationTargetException, IllegalAccessException,
            AuthenticationFailedException, NoSuchFieldException {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put("UserNameAttributeClaimUri", userNameUri);
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig(dummyUserName, true, parameterMap);

        processAuthenticationResponseStartUp();

        when(mockRequest.getParameter("chkRemember")).thenReturn(chkRemember);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        mockStatic(UserCoreUtil.class);
        when(UserCoreUtil.getDomainFromThreadLocal()).thenReturn(domainName);

        RealmConfiguration mockRealmConfiguration = mock(RealmConfiguration.class);

        if (StringUtils.isNotBlank(domainName)) {
            when(mockUserStoreManager.getSecondaryUserStoreManager(dummyDomainName)).thenReturn(mockUserStoreManager);
        }

        when(mockUserStoreManager
                .getRealmConfiguration()).thenReturn(mockRealmConfiguration);

        when(mockRealmConfiguration.getUserStoreProperty("MultipleAttributeEnable"))
                .thenReturn(multipleAttributeEnable);

        when(mockUserStoreManager.
                getUserClaimValue(MultitenantUtils.getTenantAwareUsername(dummyUserName), dummyUserName, null))
                .thenReturn(userNameValue);

        when(MultitenantUtils.getTenantDomain(dummyUserName)).thenReturn("dummyTenantDomain");
        when(FrameworkUtils.prependUserStoreDomainToName(userNameValue)).thenReturn(dummyDomainName +
                CarbonConstants.DOMAIN_SEPARATOR + userNameValue);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getPrimaryDomainName()).thenReturn(dummyDomainName);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                authenticatedUser = (AuthenticatedUser) invocation.getArguments()[0];
                return null;
            }
        }).when(mockAuthnCtxt).setSubject(any(AuthenticatedUser.class));

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                isrememberMe = (Boolean) invocation.getArguments()[0];
                return null;
            }
        }).when(mockAuthnCtxt).setRememberMe(anyBoolean());

        Map<String, Object> mockedThreadLocalMap = new HashMap<>();
        mockedThreadLocalMap.put("userExistThreadLocalProperty", false);
        IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

        when(IdentityUtil.getProperty(BasicAuthenticatorConstants.AUTHENTICATION_POLICY_CONFIG)).
                thenReturn("true");
        IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                .ErrorCode.USER_DOES_NOT_EXIST);
        ThreadLocal<IdentityErrorMsgContext> IdentityError = new ThreadLocal();
        IdentityError.set(customErrorMessageContext);

        basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);

        if (StringUtils.isNotBlank(userNameValue)) {
            assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), dummyDomainName +
                    CarbonConstants.DOMAIN_SEPARATOR + userNameValue + "@" + "dummyTenantDomain");
        } else {
            assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), dummyUserName);
        }
        if (Boolean.valueOf(chkRemember)) {
            assertEquals(isrememberMe, (Boolean) true);
        }
    }

    private void processAuthenticationResponseStartUp() throws UserStoreException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.getProperties()).thenReturn(null);

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(dummyUserName);

        mockResponse = mock(HttpServletResponse.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(dummyTenantId);

        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockRealmService = mock(RealmService.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId)).thenReturn(mockRealm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(dummyUserName)).thenReturn(dummyUserName);
        when(mockUserStoreManager.authenticate(
                MultitenantUtils.getTenantAwareUsername(dummyUserName), dummyUserName)).thenReturn(true);

        mockUser = mock(User.class);
        when(mockUser.getUserName()).thenReturn(dummyUserName);
        mockStatic(User.class);
        when(User.getUserFromUserName(anyString())).thenReturn(mockUser);

        mockStatic(FrameworkUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("carbon.super");
        when(FrameworkUtils.prependUserStoreDomainToName(anyString())).thenReturn(dummyUserName);
        when(FrameworkUtils.preprocessUsername(dummyUserName, mockAuthnCtxt)).thenReturn(dummyUserName);
    }

    @Test
    public void processAuthenticationResponseTestcaseWithuserStoreException()
            throws IOException, UserStoreException, NoSuchFieldException, IllegalAccessException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.getProperties()).thenReturn(null);

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(dummyUserName);

        mockResponse = mock(HttpServletResponse.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(-1234);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.preprocessUsername(dummyUserName, mockAuthnCtxt)).thenReturn(dummyUserName);

        mockStatic(User.class);
        mockUser = mock(User.class);
        when(User.getUserFromUserName(anyString())).thenReturn(mockUser);

        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockRealmService = mock(RealmService.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);

        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId))
                .thenReturn(mockRealm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(dummyUserName)).thenReturn(dummyUserName);

        when(mockUserStoreManager.authenticate(dummyUserName, dummyUserName)).thenThrow(
                new org.wso2.carbon.user.core.UserStoreException(
                        new org.wso2.carbon.user.core.UserStoreClientException()));
        try {
            basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
        } catch (AuthenticationFailedException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void processAuthenticationResponseTestcaseWithUserStoreClientException() throws Exception {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.getProperties()).thenReturn(null);

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(dummyUserName);

        mockResponse = mock(HttpServletResponse.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(-1234);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.preprocessUsername(dummyUserName, mockAuthnCtxt)).thenReturn(dummyUserName);

        mockStatic(User.class);
        mockUser = mock(User.class);
        when(User.getUserFromUserName(anyString())).thenReturn(mockUser);

        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockRealmService = mock(RealmService.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId))
                .thenReturn(mockRealm);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(dummyUserName)).thenReturn(dummyUserName);

        when(mockUserStoreManager.authenticate(dummyUserName, dummyUserName))
                .thenThrow(new org.wso2.carbon.user.core.UserStoreClientException());
        try {
            basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
        } catch (AuthenticationFailedException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void getUserStoreManagerException() throws Exception {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        when(mockAuthnCtxt.getProperties()).thenReturn(null);

        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(dummyUserName);

        mockResponse = mock(HttpServletResponse.class);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantIdOfUser(dummyUserName)).thenReturn(-1234);

        mockStatic(FrameworkUtils.class);
        when(FrameworkUtils.preprocessUsername(dummyUserName, mockAuthnCtxt)).thenReturn(dummyUserName);

        mockStatic(User.class);
        mockUser = mock(User.class);
        when(User.getUserFromUserName(anyString())).thenReturn(mockUser);

        mockStatic(BasicAuthenticatorServiceComponent.class);
        mockRealmService = mock(RealmService.class);
        when(BasicAuthenticatorServiceComponent.getRealmService()).thenReturn(mockRealmService);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(UserStoreManager.class);
        when(BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(dummyTenantId))
                .thenThrow(new org.wso2.carbon.user.api.UserStoreException());
        try {
            basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
        } catch (AuthenticationFailedException e) {
            assertNotNull(e);
        }
    }

    @DataProvider(name = "statusProvider")
    public Object[][] getStatus() {

        return new Boolean[][]{
                {true},
                {false}
        };
    }

    @DataProvider(name = "enableStatusProvider")
    public Object[][] getEnabledOption() {

        return new String[][]{
                {"true", dummyVal, null},
                {"false", null, null},
                {"true", null, "false"}
        };
    }

    @Test(dataProvider = "enableStatusProvider")
    public void initiateAuthenticationRequestTestcaseWithUnknownErrorCode(String statusProvider, String
            showAuthFailureReason, String cntxpropUserTenantDomainMismatch) throws
            AuthenticationFailedException, IOException, NoSuchFieldException, IllegalAccessException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> paramMap = new HashMap<>();
        paramMap.put("showAuthFailureReason", showAuthFailureReason);

        authenticatorConfig.setParameterMap(paramMap);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(Boolean.valueOf(cntxpropUserTenantDomainMismatch));
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(mockAuthnCtxt.isRetrying()).thenReturn(Boolean.valueOf(statusProvider));

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());

        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn("dummyErrorCode");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(mockIdentityErrorMsgContext);

        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);

        if (Boolean.valueOf(statusProvider) && !Boolean.valueOf(cntxpropUserTenantDomainMismatch)) {
            assertEquals(redirect, dummyLoginPage + "?" + dummyQueryParam
                    + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                    BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=login.fail.message");
        } else if (!Boolean.valueOf(statusProvider) && !Boolean.valueOf(cntxpropUserTenantDomainMismatch)) {
            assertEquals(redirect, dummyLoginPage + "?" + dummyQueryParam
                    + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                    BasicAuthenticatorConstants.LOCAL + "");
        } else {
            assertEquals(redirect, dummyLoginPage + "?" + dummyQueryParam
                    + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                    BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch" +
                    ".message");
        }
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithException() throws IOException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);

        when(mockRequest.getParameter
                (BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString())).thenReturn(null);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                isUserTenantDomainMismatch = (Boolean) invocation.getArguments()[1];
                return null;
            }
        }).when(mockAuthnCtxt).setProperty(anyString(), anyBoolean());

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        mockStatic(User.class);
        User user = new User();
        user.setUserName(dummyUserName);
        when(User.getUserFromUserName(dummyUserName)).thenReturn(user);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                throw new IOException();
            }
        }).when(mockResponse).sendRedirect(anyString());

        try {
            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
        } catch (AuthenticationFailedException ex) {
            assertEquals(ex.getUser().getUserName(), dummyUserName);
        }
    }

    @Test(dataProvider = "statusProvider")
    public void initiateAuthenticationRequestTestcaseWithoutErrorCtxt(boolean isDebugEnabled) throws
            AuthenticationFailedException, IOException, NoSuchFieldException, IllegalAccessException {

        initiateAuthenticationRequest();
        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
        assertEquals(isUserTenantDomainMismatch, (Boolean) false);
        assertEquals(redirect, dummyLoginPage + "?" + dummyQueryParam
                + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch" +
                ".message");
    }

    @DataProvider(name = "captchaConfigData")
    public Object[][] getCaptchaConfig() {

        String basicUrl = dummyLoginPage + "?" + dummyQueryParam + BasicAuthenticatorConstants
                .AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                BasicAuthenticatorConstants.LOCAL +
                BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "user.tenant.domain.mismatch.message";

        String captchaParams = BasicAuthenticatorConstants.RECAPTCHA_PARAM + "true" +
                BasicAuthenticatorConstants.RECAPTCHA_KEY_PARAM + "dummySiteKey" +
                BasicAuthenticatorConstants.RECAPTCHA_API_PARAM + "dummyApiUrl";

        return new String[][]{
                {"true", "true", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl + captchaParams},
                {"true", "true", "", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl},
                {"true", "true", "dummySiteKey", "", "dummySecret", "dummyUrl", basicUrl},
                {"true", "false", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl},
                {"false", "true", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl},
                {"false", "false", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl}
        };
    }

    @Test(dataProvider = "captchaConfigData")
    public void initiateAuthenticationRequestWithCaptchaEnabled(String parametersInUrlEnabled, String captchaEnable,
            String captchaKey, String captchaApi, String captchaSecret, String captchaUrl, String expectedRedirectUrl)
            throws Exception {

        mockStatic(IdentityUtil.class);

        Property[] captchaProperties = new Property[1];
        Property captchaEnabled = new Property();
        captchaEnabled.setName(defaultCaptchaConfigName);
        captchaEnabled.setValue("true");
        captchaProperties[0] = captchaEnabled;

        when(governanceService.getConfiguration(any(String[].class), anyString())).thenReturn(captchaProperties);
        Properties properties = new Properties();
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_PARAMETERS_IN_URL_ENABLED, parametersInUrlEnabled);
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_ENABLED, captchaEnable);
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_SITE_KEY, captchaKey);
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_API_URL, captchaApi);
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_SECRET_KEY, captchaSecret);
        properties.setProperty(CaptchaConstants.RE_CAPTCHA_VERIFY_URL, captchaUrl);

        BasicAuthenticatorDataHolder.getInstance().setRecaptchaConfigs(properties);
        BasicAuthenticatorDataHolder.getInstance().setIdentityGovernanceService(governanceService);

        initiateAuthenticationRequest();
        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
        assertEquals(isUserTenantDomainMismatch, (Boolean) false);
        assertEquals(redirect, expectedRedirectUrl);
    }

    @DataProvider(name = "errorCodeProvider")
    public Object[][] getErrorcodes() throws UnsupportedEncodingException {

        String super_tenant = "carbon.super";
        return new String[][]{
                {
                        IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE,
                        dummyLoginPage + "?" + dummyQueryParam + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE + BasicAuthenticatorConstants
                                .AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                                BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=account.confirmation.pending", "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE,
                        dummyLoginPage + "?" + dummyQueryParam +
                                BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(dummyUserName,
                                BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE +
                                BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME +
                                ":" + BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=password.reset.pending", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + ":dummyerrorcode",
                        dummyLoginPage + "?" + dummyQueryParam
                                + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME +
                                ":" + BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user" +
                                ".tenant.domain.mismatch.message" + BasicAuthenticatorConstants.ERROR_CODE +
                                UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + BasicAuthenticatorConstants.FAILED_USERNAME +
                                URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                "&remainingAttempts=" + 2, "3", "1"

                },
                {
                        UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + ":",
                        dummyLoginPage + "?" + dummyQueryParam
                                + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME +
                                ":" + BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user" +
                                ".tenant.domain.mismatch.message" + BasicAuthenticatorConstants.ERROR_CODE +
                                UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + BasicAuthenticatorConstants.FAILED_USERNAME +
                                URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                "&remainingAttempts=" + 2, "3", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST, dummyLoginPage + "?" +
                        dummyQueryParam + BasicAuthenticatorConstants.AUTHENTICATORS +
                        BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" + BasicAuthenticatorConstants.LOCAL +
                        "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message" +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(dummyUserName,
                        BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE, dummyLoginPage + "?" + dummyQueryParam
                        + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                        BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                        + BasicAuthenticatorConstants.ERROR_CODE + IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE
                        + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                        .encode(dummyUserName, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE,
                        dummyLoginPage + "?" + dummyQueryParam + BasicAuthenticatorConstants.FAILED_USERNAME +
                                URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE +
                                BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME +
                                ":" + BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=login.fail.message", "1", "1"
                },
                {
                        "dummycode", dummyLoginPage + "?" + dummyQueryParam
                        + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                        + BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                        + BasicAuthenticatorConstants.ERROR_CODE + "dummycode" + BasicAuthenticatorConstants.FAILED_USERNAME +
                        URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED, dummyEncodedVal +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(dummyUserName,
                        BasicAuthenticatorConstants.UTF_8) + "&remainingAttempts=0", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":dummyReason", dummyEncodedVal +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        "&lockedReason=dummyReason" + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode
                        (dummyUserName, BasicAuthenticatorConstants.UTF_8) + "&remainingAttempts=0", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED, dummyEncodedVal +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(dummyUserName,
                        BasicAuthenticatorConstants.UTF_8), "4", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":dummyReason", dummyEncodedVal +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        "&lockedReason=dummyReason" + BasicAuthenticatorConstants.FAILED_USERNAME +
                        URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8), "4", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE, "accountrecoveryendpoint/confirmrecovery.do?" + dummyQueryParam +
                        BasicAuthenticatorConstants.USER_NAME_PARAM + URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                        BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM + URLEncoder.encode(super_tenant, BasicAuthenticatorConstants.UTF_8) +
                        BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(dummyPassword, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE,
                        "accountrecoveryendpoint/confirmrecovery.do?" + dummyQueryParam +
                                BasicAuthenticatorConstants.USER_NAME_PARAM +
                                URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM +
                                URLEncoder.encode(super_tenant, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(dummyPassword,
                                BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.CALLBACK_PARAM +
                                URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.REASON_PARAM +
                                URLEncoder.encode(RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name(),
                                        BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE,
                        dummyLoginPage + "?" + dummyQueryParam + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(dummyUserName, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE +
                                BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.
                                AUTHENTICATOR_NAME + ":" + BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=account.pending.approval", "1", "1"
                }
        };
    }

    @DataProvider(name = "omitErrorParamsProvider")
    public Object[][] omitErrorParamsProvider() {

        return new String[][]{
                {
                        "failedUsername, remainingAttempts"
                },
                {
                        "remainingAttempts"
                },
                {
                        "errorCode, remainingAttempts"
                }
        };
    }

    @Test(dataProvider = "errorCodeProvider")
    public void initiateAuthenticationRequestTestcaseWithErrorCode(String errorCode, String expected, String maxLogin,
                                                                   String minLogin) throws AuthenticationFailedException,
            IOException, NoSuchFieldException, IllegalAccessException, URISyntaxException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        mockResponse = mock(HttpServletResponse.class);
        when(mockResponse.encodeRedirectURL(dummyRetryURL + "?" + dummyQueryParam)).thenReturn(dummyEncodedVal);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);

        AuthenticatorConfig mockAuthenticatorConfig = mock(AuthenticatorConfig.class);
        HashMap<String, String> paramMap = new HashMap<>();
        paramMap.put("showAuthFailureReason", "true");
        when(mockAuthenticatorConfig.getParameterMap()).thenReturn(paramMap);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString())).thenReturn(mockAuthenticatorConfig);

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(dummyPassword);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL()).thenReturn(dummyRetryURL);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn(errorCode);
        when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(Integer.valueOf(maxLogin));
        when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(Integer.valueOf(minLogin));

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(mockIdentityErrorMsgContext);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());

        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
        validateResponseParams(expected, redirect);
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithUserNotFoundErrorCodeMasking()
            throws AuthenticationFailedException, IOException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        mockResponse = mock(HttpServletResponse.class);
        when(mockResponse.encodeRedirectURL(dummyRetryURL + "?" + dummyQueryParam)).thenReturn(dummyEncodedVal);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);

        AuthenticatorConfig mockAuthenticatorConfig = mock(AuthenticatorConfig.class);
        HashMap<String, String> paramMap = new HashMap<>();
        paramMap.put("showAuthFailureReason", "true");
        paramMap.put("maskUserNotExistsErrorCode", "true");
        when(mockAuthenticatorConfig.getParameterMap()).thenReturn(paramMap);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(mockAuthenticatorConfig);

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(dummyPassword);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL()).thenReturn(dummyRetryURL);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
        when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
        when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(mockIdentityErrorMsgContext);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());

        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
        if (StringUtils.contains(redirect,UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
            Assert.fail("Response contains error code for USER_DOES_NOT_EXIST: "
                    + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST + ". Response: " + redirect);
        }
    }

    @Test(dataProvider = "omitErrorParamsProvider")
    public void initiateAuthenticationRequestTestcaseWithOmittedErrorParams(String omittedParams)
            throws AuthenticationFailedException, IOException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        mockResponse = mock(HttpServletResponse.class);
        when(mockResponse.encodeRedirectURL(dummyRetryURL + "?" + dummyQueryParam)).thenReturn(dummyEncodedVal);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);

        AuthenticatorConfig mockAuthenticatorConfig = mock(AuthenticatorConfig.class);
        HashMap<String, String> paramMap = new HashMap<>();
        paramMap.put("showAuthFailureReason", "true");
        paramMap.put("errorParamsToOmit", omittedParams);
        when(mockAuthenticatorConfig.getParameterMap()).thenReturn(paramMap);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(mockAuthenticatorConfig);

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(dummyPassword);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL()).thenReturn(dummyRetryURL);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
        when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
        when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(mockIdentityErrorMsgContext);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());

        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);

        omittedParams = omittedParams.replace(" ","");
        List<String> omittedParamList = new ArrayList<>(Arrays.asList(omittedParams.split(",")));

        for (String omittedParam : omittedParamList) {
            if (redirect.contains(omittedParam)) {
                Assert.fail("Response contains omitted param: " + omittedParam + ". Response: " + redirect);
            }
        }
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithPasswordResetErrorOmitted()
            throws AuthenticationFailedException, IOException, URISyntaxException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(dummyUserName);
        mockResponse = mock(HttpServletResponse.class);
        when(mockResponse.encodeRedirectURL(dummyRetryURL + "?" + dummyQueryParam)).thenReturn(dummyEncodedVal);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);

        AuthenticatorConfig mockAuthenticatorConfig = mock(AuthenticatorConfig.class);
        HashMap<String, String> paramMap = new HashMap<>();
        paramMap.put("maskAdminForcedPasswordResetErrorCode", "true");
        when(mockAuthenticatorConfig.getParameterMap()).thenReturn(paramMap);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(mockAuthenticatorConfig);

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(dummyPassword);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL()).thenReturn(dummyRetryURL);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        when(mockIdentityErrorMsgContext.getErrorCode())
                .thenReturn(IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
        when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
        when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(mockIdentityErrorMsgContext);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());

        basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);

        validateResponseParam(BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM.replaceAll("&", ""), redirect,
                "login.fail.message");
    }

    private void validateResponseParam(String param, String actual, String expected) throws URISyntaxException {

        URI actualURI = new URI(URLDecoder.decode(actual));
        String[] actualQueryParams = actualURI.getQuery().split("&");

        for (String actualQueryParam : actualQueryParams) {
            if (actualQueryParam.contains(param) && !actualQueryParam.contains(expected)) {
                Assert.fail("Expected param: '" + actualQueryParam + "'  not available in response: " + actual);
            }
        }
    }

    private void validateResponseParams(String expected, String actual) throws URISyntaxException {

        URI expectedURI = new URI(expected);
        String[] expectedQueryParams = expected.split("&");

        for (String expectedQueryParam : expectedQueryParams) {
            if (!actual.contains(expectedQueryParam)) {
                Assert.fail("Expected param: '" + expectedQueryParam + "'  not available in response: " + actual);
            }
        }
    }

    private void initiateAuthenticationRequest() throws IOException {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);

        mockStatic(FileBasedConfigurationBuilder.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockFileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString())).thenReturn(null);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                isUserTenantDomainMismatch = (Boolean) invocation.getArguments()[1];
                return null;
            }
        }).when(mockAuthnCtxt).setProperty(anyString(), anyBoolean());

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(dummyQueryParam);
        when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(dummyLoginPage);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        doAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockResponse).sendRedirect(anyString());
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
