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

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginUtilities;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.recovery.RecoveryScenarios;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.CONTENT;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.COOKIE_NAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.CREATED_TIME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.DEFAULT_COOKIE_MAX_AGE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.DOMAIN;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.FLOW_TYPE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.RECOVERY;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.RECOVERY_ADMIN_PASSWORD_RESET_AUTO_LOGIN;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SIGNATURE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.SIGNUP;
import static org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant.USERNAME;

/**
 * Unit test cases for the Basic Authenticator.
 */
public class BasicAuthenticatorTestCase {

    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;
    private AuthenticationContext mockAuthnCtxt;
    private ApplicationConfig applicationConfig;
    private RealmService mockRealmService;
    private UserRealm mockRealm;
    private AbstractUserStoreManager mockUserStoreManager;
    private FileBasedConfigurationBuilder mockFileBasedConfigurationBuilder;
    private IdentityErrorMsgContext mockIdentityErrorMsgContext;
    private TenantManager mockTenantManager;
    private IdentityGovernanceService mockGovernanceService;
    private RealmConfiguration mockRealmConfiguration;
    private ConfigurationFacade mockConfigurationFacade;
    private MultiAttributeLoginService mockMultiAttributeLoginService;
    private ConfigurationContextService mockConfigurationContextService;
    private ConfigurationContext mockConfigurationContext;
    private AxisConfiguration mockAxisConfiguration;
    private PrivilegedCarbonContext mockPrivilegedCarbonContext;
    private ServerConfiguration mockServerConfiguration;

    private AuthenticatedUser authenticatedUser;
    private Boolean isRememberMe = false;
    private Boolean isUserTenantDomainMismatch = true;
    private String redirect;

    private static final String DUMMY_USER_NAME = "dummyUserName";
    private static final String DUMMY_PASSWORD = "dummyPassword";
    private static final String DUMMY_QUERY_PARAMS = "dummyQueryParams";
    private static final String DUMMY_LOGIN_PAGEURL = "dummyLoginPageurl";
    private static final String DUMMY_DOMAIN = "dummyDomain";
    private static final String DUMMY_RETRY_URL = "DummyRetryUrl";
    private static final String DUMMY_RETRY_URL_WITH_QUERY = "DummyRetryUrl?dummyQueryParams";
    private static final String DUMMY_PROTOCOL = "https";
    private static final String DUMMY_HOSTNAME = "localhost";
    private static final int DUMMY_PORT = 9443;

    private final BasicAuthenticator basicAuthenticator = new BasicAuthenticator();

    @BeforeTest
    public void setup() {

        System.setProperty("carbon.config.dir.path", "carbon.home");
    }

    @BeforeMethod
    public void init() throws IdentityGovernanceException {
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockAuthnCtxt = mock(AuthenticationContext.class);
        applicationConfig = mock(ApplicationConfig.class);
        mockRealmService = mock(RealmService.class);
        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(AbstractUserStoreManager.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        mockIdentityErrorMsgContext = mock(IdentityErrorMsgContext.class);
        mockGovernanceService = mock(IdentityGovernanceService.class);
        mockRealmConfiguration = mock(RealmConfiguration.class);
        mockConfigurationFacade = mock(ConfigurationFacade.class);
        mockTenantManager = mock(TenantManager.class);
        mockMultiAttributeLoginService = mock(MultiAttributeLoginService.class);
        mockConfigurationContextService = mock(ConfigurationContextService.class);
        mockConfigurationContext = mock(ConfigurationContext.class);
        mockAxisConfiguration = mock(AxisConfiguration.class);
        mockPrivilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        mockServerConfiguration = mock(ServerConfiguration.class);

        Property[] captchaProperties = new Property[1];
        Property captchaEnabled = new Property();
        captchaEnabled.setDefaultValue("false");
        captchaProperties[0] = captchaEnabled;

        when(mockGovernanceService.getConfiguration(any(String[].class), anyString())).thenReturn(captchaProperties);
        BasicAuthenticatorDataHolder.getInstance().setIdentityGovernanceService(mockGovernanceService);
        BasicAuthenticatorDataHolder.getInstance().setMultiAttributeLogin(mockMultiAttributeLoginService);
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

        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(userName);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(password);
        assertEquals(Boolean.valueOf(expected).booleanValue(), basicAuthenticator.canHandle(mockRequest),
                "Invalid can handle response for the request.");
    }

    @Test
    public void processSuccessTestCase() throws Exception {

        when(mockAuthnCtxt.isLogoutRequest()).thenReturn(true);
        assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @DataProvider(name = "getAutoLoginCases")
    public Object[][] getAutoLoginCases() {

        String autoLoginSignature = "eyJzaWduYXR1cmUiOiJBeTRTU1h1bXlhWFpzYzBnS0J1SjdUQzgyNzEzb1BiWlRjSDZs" +
                "XFxcL29XcE1vaVNJVUFHcWwyb2tWOGZ0c3VPMWlrdUZQaUE1Qm1LNFFpdzNpakVTaXdmbFBzcmdNTVVFdEcrMnE3cEQya09oc0p" +
                "1NmVuRnQ5Qlc5THl0YjlsSmlmV0hJZXVGRDllckFyUDhiWExocTE1WFFmSnVGSlNtVnBIZTZub0RrNnVIY2ZLTW5aVmF2d0xza2" +
                "5DZE5mYnZXQitxUkF3dnJBSmtLTG9vZVZpM2t4RlBHbmcwaFlRbnNKeHJcXFwvOTNwVnpmN1xcXC9PcmZhcFU2bzJXNEZvdk01d" +
                "XJ6SjhDWmVkakpHZm5qdjV5bXNjRlN3U1NWVDljZnhISVVBWDFaQU9CZzRSMVZXNnhlbm9wcjYzTkFIYXZINFNESSs0UFl2Y1Ju" +
                "S0J1dVR5YTB0dm0rdTVUaVE9PSIsImNvbnRlbnQiOiJ7XCJ1c2VybmFtZVwiOlwiYWRtaW5cIixcImZsb3dUeXBlXCI6XCJTSUdO" +
                "VVBcIn0ifQ==";
        return new Object[][]{
                {SIGNUP, null, System.currentTimeMillis(), autoLoginSignature,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED.toString()},
                {SIGNUP, "wso2.is", null, autoLoginSignature, AuthenticatorFlowStatus.INCOMPLETE.toString()},
                {SIGNUP, "wso2.is", System.currentTimeMillis(), null, AuthenticatorFlowStatus.INCOMPLETE.toString()},
                {SIGNUP, "wso2.is", System.currentTimeMillis() -
                        TimeUnit.MINUTES.toMillis(Long.parseLong(DEFAULT_COOKIE_MAX_AGE)), autoLoginSignature,
                                AuthenticatorFlowStatus.INCOMPLETE.toString()},
                {SIGNUP, "wso2.is", System.currentTimeMillis(), autoLoginSignature,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED.toString()},
                {RECOVERY, null, System.currentTimeMillis(), autoLoginSignature,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED.toString()}
        };
    }

    @Test(dataProvider = "getAutoLoginCases")
    public void processAutoLoginNewCookieSuccessTestCase(String flowType, String domain, Long createdTime,
                                                         String signature, String status) throws Exception {

        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put("UserNameAttributeClaimUri", "http://wso2.org/claims/username");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("BasicAuthenticator", true,
                parameterMap);

        try (MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder
                     = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<Utils> utils = Mockito.mockStatic(Utils.class);
             MockedStatic<MultitenantUtils> multitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<UserCoreUtil> userCoreUtil = Mockito.mockStatic(UserCoreUtil.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorService =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<SignatureUtil> signatureUtil = Mockito.mockStatic(SignatureUtil.class)) {

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.isLogoutRequest()).thenReturn(false);
            when(mockAuthnCtxt.getTenantDomain()).thenReturn(DUMMY_DOMAIN);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn("admin");
            when((mockAuthnCtxt.getSequenceConfig())).thenReturn(new SequenceConfig());

            signatureUtil.when(() -> SignatureUtil.validateSignature(anyString(), any(byte[].class))).thenReturn(true);
            signatureUtil.when(() -> SignatureUtil.validateSignature(any(byte[].class), anyString(),
                    any(byte[].class))).thenReturn(true);
            signatureUtil.when(() -> SignatureUtil.getThumbPrintForAlias("alias")).thenReturn(new byte[0]);

            frameworkUtils.when(
                    () -> FrameworkUtils.prependUserStoreDomainToName("admin"))
                    .thenReturn("admin" + "@" + DUMMY_DOMAIN);

            utils.when(() -> Utils.getConnectorConfig(RECOVERY_ADMIN_PASSWORD_RESET_AUTO_LOGIN, DUMMY_DOMAIN))
                    .thenReturn("true");
            utils.when(() -> Utils.getConnectorConfig(SELF_REGISTRATION_AUTO_LOGIN, DUMMY_DOMAIN))
                    .thenReturn("true");
            utils.when(() -> Utils.getConnectorConfig(SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME, DUMMY_DOMAIN))
                    .thenReturn("alias");

            identityTenantUtil.when(
                    () -> IdentityTenantUtil.getTenantIdOfUser("admin" + "@" + DUMMY_DOMAIN))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            userCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn(DUMMY_DOMAIN);

            basicAuthenticatorService.when(BasicAuthenticatorServiceComponent::getRealmService)
                    .thenReturn(mockRealmService);
            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockRealm);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
            when(mockUserStoreManager.getSecondaryUserStoreManager(DUMMY_DOMAIN)).thenReturn(mockUserStoreManager);
            when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
            when(mockRealmConfiguration.getUserStoreProperty("MultipleAttributeEnable")).thenReturn("false");

            multitenantUtils.when(
                    () -> MultitenantUtils.getTenantDomain("admin" + "@" + DUMMY_DOMAIN)).thenReturn(DUMMY_DOMAIN);

            JSONObject cookieValue = new JSONObject();
            cookieValue.put(USERNAME, "admin");
            cookieValue.put(FLOW_TYPE, flowType);
            cookieValue.put(DOMAIN, domain);
            cookieValue.put(CREATED_TIME, createdTime);
            String content = cookieValue.toString();
            JSONObject cookieValueInJson = new JSONObject();
            cookieValueInJson.put(CONTENT, content);
            cookieValueInJson.put(SIGNATURE, signature);

            Cookie[] cookies = new Cookie[1];
            cookies[0] = new Cookie(COOKIE_NAME,
                    Base64.getEncoder().encodeToString(cookieValueInJson.toString().getBytes()));
            when(mockRequest.getCookies()).thenReturn(cookies);

            assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt).toString(), status);
        }
    }

    @Test
    public void processIncompleteTestCase() throws IOException, AuthenticationFailedException, LogoutFailedException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade>
                     configurationFacade = Mockito.mockStatic(ConfigurationFacade.class)) {

            initiateAuthenticationRequest(fileBasedConfigurationBuilder, configurationFacade);
            when(mockAuthnCtxt.isLogoutRequest()).thenReturn(false);
            assertEquals(basicAuthenticator.process(mockRequest, mockResponse, mockAuthnCtxt),
                    AuthenticatorFlowStatus.INCOMPLETE);
        }
    }

    @Test
    public void isEnableSelfRegistrationAutoLoginTest() throws AuthenticationFailedException {

        try (MockedStatic<Utils> utilities = Mockito.mockStatic(Utils.class)) {
            utilities.when(() -> Utils.getConnectorConfig("SelfRegistration.AutoLogin.Enable", DUMMY_DOMAIN))
                    .thenReturn("true");

            when(mockAuthnCtxt.getTenantDomain()).thenReturn(DUMMY_DOMAIN);
            assertTrue(AutoLoginUtilities.isEnableSelfRegistrationAutoLogin(mockAuthnCtxt));
        }
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

        try (MockedStatic<Utils> utilities = Mockito.mockStatic(Utils.class)) {
            utilities.when(() -> Utils.getConnectorConfig("SelfRegistration.AutoLogin.Enable", tenant))
                    .thenReturn("Error");

            when(mockAuthnCtxt.getTenantDomain()).thenReturn(tenant);
            when(Utils.getConnectorConfig("SelfRegistration.AutoLogin.Enable", tenant)).
                    thenThrow(new IdentityEventException("Error"));
            try {
                AutoLoginUtilities.isEnableSelfRegistrationAutoLogin(mockAuthnCtxt);
            } catch (Exception e) {
                assertEquals(e.getMessage(),expected);
            }
        }
    }

    @DataProvider(name = "SelfRegistrationAutoLoginAliasDataProvider")
    public Object[][] getSelfRegistrationAutoLoginAlias() {

        return new String[][] {
                {null, "Error occurred while resolving SelfRegistration.AutoLogin.AliasName property."},
        };
    }

    @Test(dataProvider = "SelfRegistrationAutoLoginAliasDataProvider")
    public void getSelfRegistrationAutoLoginAliasExceptionTest(String tenant, Object expected ) {

        try (MockedStatic<Utils> utilities = Mockito.mockStatic(Utils.class)) {

            utilities.when(() -> Utils.getConnectorConfig("SelfRegistration.AutoLogin.AliasName", tenant))
                    .thenThrow(new IdentityEventException("Error"));
            when(mockAuthnCtxt.getTenantDomain()).thenReturn(tenant);
            try {
                AutoLoginUtilities.getSelfRegistrationAutoLoginAlias(mockAuthnCtxt);
            } catch (Exception e) {
                assertEquals(e.getMessage(),expected);
            }
        }
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

        String dummySessionDataKey = "dummyVal";
        when(mockRequest.getParameter("sessionDataKey")).thenReturn(dummySessionDataKey);
        assertEquals(basicAuthenticator.getContextIdentifier(mockRequest), dummySessionDataKey);
    }

    @DataProvider(name = "realmProvider")
    public Object[][] getRealm() {

        mockRealm = mock(UserRealm.class);
        mockUserStoreManager = mock(AbstractUserStoreManager.class);

        return new Object[][]{
                {null, "Cannot find the user realm for the given tenant: " + MultitenantConstants.SUPER_TENANT_ID,
                        null, null},
                {mockRealm, "User authentication failed due to invalid credentials", "someDomain", null},
                {mockRealm, "User authentication failed due to invalid credentials", null, null},
                {mockRealm, "Credential mismatch.", null, new HashMap<String, String>() {{
                    put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, "dummyUsername2");
                }}},
        };
    }

    @Test(dataProvider = "realmProvider")
    public void processAuthenticationResponseTestCaseForException(Object realm, Object expected, Object
            recapchaUserDomain, Object authenticatorParams) throws Exception {

        try (MockedStatic<MultitenantUtils> multitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorService =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            when(mockAuthnCtxt.getProperties()).thenReturn(new HashMap<>());
            when(mockAuthnCtxt.getAuthenticatorParams("common"))
                    .thenReturn((Map<String, String>) authenticatorParams);

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_PASSWORD);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            basicAuthenticatorService
                    .when(BasicAuthenticatorServiceComponent::getRealmService).thenReturn(mockRealmService);
            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn((UserRealm) realm);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            if (realm != null) {
                when(((UserRealm) realm).getUserStoreManager()).thenReturn(mockUserStoreManager);
            }

            multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME))
                    .thenReturn(DUMMY_USER_NAME);
            multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(DUMMY_USER_NAME))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            Map<String, Object> mockedThreadLocalMap = new HashMap<>();
            mockedThreadLocalMap.put("user-domain-recaptcha", recapchaUserDomain);
            IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                    .thenReturn(DUMMY_USER_NAME);
            when(mockUserStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                    MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME), DUMMY_PASSWORD,
                    UserCoreConstants.DEFAULT_PROFILE))
                    .thenReturn(new AuthenticationResult(AuthenticationResult.AuthenticationStatus.FAIL));

            User userFromUsername = new User();
            userFromUsername.setUserName(DUMMY_USER_NAME);
            user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

            try {
                basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
            } catch (Exception ex) {
                assertEquals(ex.getMessage(), expected);
            }
        }
    }

    @DataProvider(name = "multipleAttributeprovider")
    public Object[][] getMultipleAttributeProvider() {

        String dummyUserNameValue = "dummyusernameValue";
        return new Object[][]{
                {DUMMY_DOMAIN, DUMMY_USER_NAME, "off", dummyUserNameValue, "false", false},
                {DUMMY_DOMAIN, DUMMY_USER_NAME, "off", dummyUserNameValue, "false", true},
                {DUMMY_DOMAIN, DUMMY_USER_NAME, "off", dummyUserNameValue, "true", false},
                {null, DUMMY_USER_NAME, "off", dummyUserNameValue, "true", false}
        };
    }

    @Test(dataProvider = "multipleAttributeprovider")
    public void processAuthenticationResponseTestcaseWithMultiAttribute(String domainName, String userNameUri, String
            chkRemember, String userNameValue, String oldMultipleAttributeEnable, boolean newMultipleAttributeEnable)
            throws UserStoreException, AuthenticationFailedException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<MultitenantUtils> multitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<UserCoreUtil> userCoreUtil = Mockito.mockStatic(UserCoreUtil.class);
             MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder =
                     Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorServiceComponent =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            ResolvedUserResult resolvedUserResult;
            org.wso2.carbon.user.core.common.User userObj
                    = new org.wso2.carbon.user.core.common.User("c2de9b28-f258-4df0-ba29-f4803e4e821a",
                    userNameValue, userNameValue);
            userObj.setTenantDomain("dummyTenantDomain");
            userObj.setUserStoreDomain(domainName);
            if (newMultipleAttributeEnable) {
                resolvedUserResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.SUCCESS);
                resolvedUserResult.setUser(userObj);
            } else {
                resolvedUserResult = new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.FAIL);
            }

            Map<String, String> parameterMap = new HashMap<>();
            parameterMap.put("UserNameAttributeClaimUri", userNameUri);
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig(DUMMY_USER_NAME, true, parameterMap);

            processAuthenticationResponseStartUp(identityTenantUtil, basicAuthenticatorServiceComponent,
                    multitenantUtils, user, frameworkUtils, userObj);

            when(mockRequest.getParameter("chkRemember")).thenReturn(chkRemember);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            userCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn(domainName);
            userCoreUtil.when(() -> UserCoreUtil.addTenantDomainToEntry(userNameValue, "dummyTenantDomain"))
                    .thenReturn(userNameValue + "@" + "dummyTenantDomain");

            if (StringUtils.isNotBlank(domainName)) {
                when(mockUserStoreManager.getSecondaryUserStoreManager(DUMMY_DOMAIN))
                        .thenReturn(mockUserStoreManager);
            }

            when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);

            when(mockRealmConfiguration.getUserStoreProperty("MultipleAttributeEnable"))
                    .thenReturn(oldMultipleAttributeEnable);

            if (StringUtils.isNotBlank(domainName)) {
                when(mockUserStoreManager.getSecondaryUserStoreManager(domainName)).thenReturn(mockUserStoreManager);
            }

            when(mockUserStoreManager.
                    getUserClaimValue(MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME), DUMMY_USER_NAME, null))
                    .thenReturn(userNameValue);

            frameworkUtils.when(() -> FrameworkUtils.prependUserStoreDomainToName(userNameValue))
                    .thenReturn(DUMMY_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR + userNameValue);
            frameworkUtils.when(() -> FrameworkUtils
                    .processMultiAttributeLoginIdentification(anyString(), anyString())).thenReturn(resolvedUserResult);

            identityUtil.when(IdentityUtil::getPrimaryDomainName).thenReturn(DUMMY_DOMAIN);
            identityUtil.when(() -> IdentityUtil.addDomainToName(userNameValue + "@" + "dummyTenantDomain", domainName))
                    .thenReturn(domainName + "/" + userNameValue + "@" + "dummyTenantDomain");

            doAnswer((Answer<Object>) invocation -> {

                authenticatedUser = (AuthenticatedUser) invocation.getArguments()[0];
                return null;
            }).when(mockAuthnCtxt).setSubject(any(AuthenticatedUser.class));

            doAnswer((Answer<Object>) invocation -> {

                isRememberMe = (Boolean) invocation.getArguments()[0];
                return null;
            }).when(mockAuthnCtxt).setRememberMe(anyBoolean());

            Map<String, Object> mockedThreadLocalMap = new HashMap<>();
            mockedThreadLocalMap.put("userExistThreadLocalProperty", false);
            IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

            when(IdentityUtil.getProperty(BasicAuthenticatorConstants.AUTHENTICATION_POLICY_CONFIG)).
                    thenReturn("true");
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                    .ErrorCode.USER_DOES_NOT_EXIST);
            ThreadLocal<IdentityErrorMsgContext> IdentityError = new ThreadLocal<>();
            IdentityError.set(customErrorMessageContext);

            basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);

            if (StringUtils.isNotBlank(userNameValue)) {
                assertEquals(authenticatedUser.getUserName(), userNameValue);
            } else {
                assertEquals(authenticatedUser.getAuthenticatedSubjectIdentifier(), DUMMY_USER_NAME);
            }
            if (Boolean.parseBoolean(chkRemember)) {
                assertEquals(isRememberMe, (Boolean) true);
            }
        }
    }

    private void processAuthenticationResponseStartUp(
            MockedStatic<IdentityTenantUtil> identityTenantUtil,
            MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorServiceComponent,
            MockedStatic<MultitenantUtils> multitenantUtils, MockedStatic<User> user,
            MockedStatic<FrameworkUtils> frameworkUtils, org.wso2.carbon.user.core.common.User userObj)
            throws UserStoreException {

        when(mockAuthnCtxt.getProperties()).thenReturn(null);

        when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
        when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_USER_NAME);

        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

        basicAuthenticatorServiceComponent.when(BasicAuthenticatorServiceComponent::getRealmService)
                .thenReturn(mockRealmService);
        when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockRealm);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);

        when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        multitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME))
                .thenReturn(DUMMY_USER_NAME);
        AuthenticationResult authenticationResult =
                new AuthenticationResult(AuthenticationResult.AuthenticationStatus.SUCCESS);
        authenticationResult.setAuthenticatedUser(userObj);
        when(mockUserStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME), DUMMY_USER_NAME,
                UserCoreConstants.DEFAULT_PROFILE))
                .thenReturn(authenticationResult);
        when(mockUserStoreManager.authenticateWithID(userObj.getUserID(), DUMMY_USER_NAME))
                .thenReturn(authenticationResult);

        User userFromUsername = new User();
        userFromUsername.setUserName(DUMMY_USER_NAME);
        user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

        multitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString())).thenReturn("carbon.super");
        frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                .thenReturn(DUMMY_USER_NAME);
    }

    @Test
    public void processAuthenticationResponseTestcaseWithUserStoreExceptionInAuthenticate() throws UserStoreException {

        try (MockedStatic<MultitenantUtils> multitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorService =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            when(mockAuthnCtxt.getProperties()).thenReturn(null);

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_PASSWORD);

            when(mockAuthnCtxt.getAuthenticatorParams("common")).thenReturn(anyMap());
            when(mockAuthnCtxt.getAuthenticatorParams("BasicAuthenticator")).thenReturn(anyMap());
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                    .thenReturn(DUMMY_USER_NAME);

            User userFromUsername = new User();
            user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

            Map<String, Object> mockedThreadLocalMap = new HashMap<>();
            IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

            basicAuthenticatorService
                    .when(BasicAuthenticatorServiceComponent::getRealmService).thenReturn(mockRealmService);
            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockRealm);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

            multitenantUtils.when(
                    () -> MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockUserStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                    MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME), DUMMY_PASSWORD,
                    UserCoreConstants.DEFAULT_PROFILE))
                    .thenThrow(new org.wso2.carbon.user.core.UserStoreException(new UserStoreClientException()));
            try {
                basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
            } catch (AuthenticationFailedException e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void processAuthenticationResponseTestcaseWithUserStoreClientException() throws UserStoreException {

        try (MockedStatic<MultitenantUtils> multitenantUtils = Mockito.mockStatic(MultitenantUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorService =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            when(mockAuthnCtxt.getProperties()).thenReturn(null);

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_PASSWORD);

            when(mockAuthnCtxt.getAuthenticatorParams("common")).thenReturn(anyMap());
            when(mockAuthnCtxt.getAuthenticatorParams("BasicAuthenticator")).thenReturn(anyMap());

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME))
                    .thenReturn(MultitenantConstants.SUPER_TENANT_ID);

            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                    .thenReturn(DUMMY_USER_NAME);

            User userFromUsername = new User();
            user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

            Map<String, Object> mockedThreadLocalMap = new HashMap<>();
            IdentityUtil.threadLocalProperties.set(mockedThreadLocalMap);

            basicAuthenticatorService.when(BasicAuthenticatorServiceComponent::getRealmService)
                    .thenReturn(mockRealmService);

            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockRealm);
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);

            when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            when(mockRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

            multitenantUtils.when(
                    () -> MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockUserStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                    MultitenantUtils.getTenantAwareUsername(DUMMY_USER_NAME), DUMMY_PASSWORD,
                    UserCoreConstants.DEFAULT_PROFILE))
                    .thenThrow(new UserStoreClientException());
            try {
                basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
            } catch (AuthenticationFailedException e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void processAuthenticationResponseTestcaseWithUserStoreManagerException() throws Exception {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorServiceComponent =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            when(mockAuthnCtxt.getProperties()).thenReturn(null);

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_USER_NAME);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME)).thenReturn(-1234);

            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                    .thenReturn(DUMMY_USER_NAME);

            User userFromUsername = new User();
            user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

            basicAuthenticatorServiceComponent
                    .when(BasicAuthenticatorServiceComponent::getRealmService).thenReturn(mockRealmService);
            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID))
                    .thenThrow(new org.wso2.carbon.user.api.UserStoreException());
            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            try {
                basicAuthenticator.processAuthenticationResponse(mockRequest, mockResponse, mockAuthnCtxt);
            } catch (AuthenticationFailedException e) {
                assertNotNull(e);
            }
        }
    }

    @Test
    public void processAuthenticationResponseTestcaseWithUserStoreExceptionInGetTenantId() throws UserStoreException {

        try (MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class);
             MockedStatic<BasicAuthenticatorServiceComponent> basicAuthenticatorServiceComponent =
                     Mockito.mockStatic(BasicAuthenticatorServiceComponent.class)) {

            when(mockAuthnCtxt.getProperties()).thenReturn(null);

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.PASSWORD)).thenReturn(DUMMY_USER_NAME);

            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantIdOfUser(DUMMY_USER_NAME))
                    .thenThrow(new IdentityRuntimeException("Invalid tenant domain of user admin@abc.com"));

            frameworkUtils.when(() -> FrameworkUtils.preprocessUsername(DUMMY_USER_NAME, mockAuthnCtxt))
                    .thenReturn(DUMMY_USER_NAME);

            User userFromUsername = new User();
            user.when(() -> User.getUserFromUserName(anyString())).thenReturn(userFromUsername);

            basicAuthenticatorServiceComponent
                    .when(BasicAuthenticatorServiceComponent::getRealmService).thenReturn(mockRealmService);

            when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
            when(mockTenantManager.getTenantId(anyString()))
                    .thenThrow(new org.wso2.carbon.user.api.UserStoreException("Invalid tenant domain of user admin@abc" +
                            ".com"));
            when(mockRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockRealm);
            try {
                basicAuthenticator.processAuthenticationResponse(
                        mockRequest, mockResponse, mockAuthnCtxt);
            } catch (AuthenticationFailedException e) {
                assertNotNull(e);
            }
        }
    }


    @DataProvider(name = "enableStatusProvider")
    public Object[][] getEnabledOption() {

        return new String[][]{
                {"true", "dummyReason", null, null},
                {"false", null, null, null},
                {"true", null, "false", null},
                {"true", null, "false", "true"}
        };
    }

    @Test(dataProvider = "enableStatusProvider")
    public void initiateAuthenticationRequestTestcaseWithUnknownErrorCode(String statusProvider, String
            showAuthFailureReason, String constexprUserTenantDomainMismatch, String contextInvalidEmailUsername) throws
            AuthenticationFailedException, IOException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<ConfigurationFacade> configurationFacade = Mockito.mockStatic(ConfigurationFacade.class)) {

            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map<String, String> paramMap = new HashMap<>();
            paramMap.put("showAuthFailureReason", showAuthFailureReason);

            authenticatorConfig.setParameterMap(paramMap);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(Boolean.valueOf(
                    constexprUserTenantDomainMismatch));
            when(mockAuthnCtxt.getProperty("InvalidEmailUsername"))
                    .thenReturn(Boolean.valueOf(contextInvalidEmailUsername));
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);

            configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
            when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(Boolean.valueOf(statusProvider));

            doAnswer((Answer<Object>) invocation -> {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }).when(mockResponse).sendRedirect(anyString());

            when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn("dummyErrorCode");

            identityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(mockIdentityErrorMsgContext);

            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);

            if (Boolean.parseBoolean(statusProvider) && !Boolean.parseBoolean(constexprUserTenantDomainMismatch)
                    && !Boolean.parseBoolean(contextInvalidEmailUsername)) {
                assertEquals(redirect, DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                        + BasicAuthenticatorConstants.AUTHENTICATORS
                        + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                        + BasicAuthenticatorConstants.LOCAL + "&authFailure=true&authFailureMsg=login.fail.message");
            } else if (!Boolean.parseBoolean(statusProvider)
                    && !Boolean.parseBoolean(constexprUserTenantDomainMismatch)) {
                assertEquals(redirect, DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                        + BasicAuthenticatorConstants.AUTHENTICATORS
                        + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                        + BasicAuthenticatorConstants.LOCAL + "");
            } else if (Boolean.parseBoolean(statusProvider) && Boolean.parseBoolean(contextInvalidEmailUsername)) {
                assertEquals(redirect, DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                        + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME
                        + ":" + BasicAuthenticatorConstants.LOCAL
                        + "&authFailure=true&authFailureMsg=emailusername.fail.message");
            } else {
                assertEquals(redirect, DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                        + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME
                        + ":" + BasicAuthenticatorConstants.LOCAL
                        + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message");
            }
        }
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithException() throws IOException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<User> user = Mockito.mockStatic(User.class)) {

            when(mockRequest.getParameter
                    (BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);

            doAnswer((Answer<Object>) invocation -> {

                isUserTenantDomainMismatch = (Boolean) invocation.getArguments()[1];
                return null;
            }).when(mockAuthnCtxt).setProperty(anyString(), anyBoolean());

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
            when(ConfigurationFacade.getInstance().getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(true);

            User userFromName = new User();
            userFromName.setUserName(DUMMY_USER_NAME);
            user.when(() -> User.getUserFromUserName(DUMMY_USER_NAME)).thenReturn(userFromName);

            doAnswer((Answer<Object>) invocation -> {

                throw new IOException();
            }).when(mockResponse).sendRedirect(anyString());

            try {
                basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
            } catch (AuthenticationFailedException ex) {
                assertEquals(ex.getUser().getUserName(), DUMMY_USER_NAME);
            }
        }
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithoutErrorCtxt() throws
            AuthenticationFailedException, IOException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade>
                     configurationFacade = Mockito.mockStatic(ConfigurationFacade.class)) {

            initiateAuthenticationRequest(fileBasedConfigurationBuilder, configurationFacade);
            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
            assertEquals(isUserTenantDomainMismatch, (Boolean) false);
            assertEquals(redirect, DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                    + BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME
                    + ":" + BasicAuthenticatorConstants.LOCAL
                    + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message");
        }
    }

    @DataProvider(name = "captchaConfigData")
    public Object[][] getCaptchaConfig() {

        String basicUrl = DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS + BasicAuthenticatorConstants
                .AUTHENTICATORS + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" +
                BasicAuthenticatorConstants.LOCAL +
                BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "user.tenant.domain.mismatch.message";

        String captchaParams = BasicAuthenticatorConstants.RECAPTCHA_PARAM + "true" +
                BasicAuthenticatorConstants.RECAPTCHA_KEY_PARAM + "dummySiteKey" +
                BasicAuthenticatorConstants.RECAPTCHA_API_PARAM + "dummyApiUrl";

        return new String[][]{
                {"true", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl + captchaParams},
                {"true", "", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl},
                {"true", "dummySiteKey", "", "dummySecret", "dummyUrl", basicUrl},
                {"false", "dummySiteKey", "dummyApiUrl", "dummySecret", "dummyUrl", basicUrl},
        };
    }

    @Test(dataProvider = "captchaConfigData")
    public void initiateAuthenticationRequestWithCaptchaEnabled(String captchaEnable, String captchaKey, String
            captchaApi, String captchaSecret, String captchaUrl, String expectedRedirectUrl) throws Exception {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade>
                     configurationFacade = Mockito.mockStatic(ConfigurationFacade.class)) {

            Property[] captchaProperties = new Property[1];
            Property captchaEnabled = new Property();
            String defaultCaptchaConfigName = "sso.login.recaptcha" +
                    CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;
            captchaEnabled.setName(defaultCaptchaConfigName);
            captchaEnabled.setValue("true");
            captchaProperties[0] = captchaEnabled;

            when(mockGovernanceService.getConfiguration(any(String[].class), anyString()))
                    .thenReturn(captchaProperties);
            Properties properties = new Properties();
            properties.setProperty(CaptchaConstants.RE_CAPTCHA_ENABLED, captchaEnable);
            properties.setProperty(CaptchaConstants.RE_CAPTCHA_SITE_KEY, captchaKey);
            properties.setProperty(CaptchaConstants.RE_CAPTCHA_API_URL, captchaApi);
            properties.setProperty(CaptchaConstants.RE_CAPTCHA_SECRET_KEY, captchaSecret);
            properties.setProperty(CaptchaConstants.RE_CAPTCHA_VERIFY_URL, captchaUrl);

            BasicAuthenticatorDataHolder.getInstance().setRecaptchaConfigs(properties);

            when(mockAuthnCtxt.getLoginTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            initiateAuthenticationRequest(fileBasedConfigurationBuilder, configurationFacade);
            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
            assertEquals(isUserTenantDomainMismatch, (Boolean) false);
            assertEquals(redirect, expectedRedirectUrl);
        }
    }

    @DataProvider(name = "errorCodeProvider")
    public Object[][] getErrorcodes() throws UnsupportedEncodingException {

        String super_tenant = "carbon.super";
        String callbackUrl =
                String.format("%s://%s:%s/%s", DUMMY_PROTOCOL, DUMMY_HOSTNAME, DUMMY_PORT, DUMMY_LOGIN_PAGEURL);
        String callback = callbackUrl + "?" + DUMMY_QUERY_PARAMS + "&authenticators=BasicAuthenticator";
        return new String[][]{
                {
                        IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE,
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8)
                                + BasicAuthenticatorConstants.ERROR_CODE
                                + IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE
                                + BasicAuthenticatorConstants.AUTHENTICATORS
                                + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                                + BasicAuthenticatorConstants.LOCAL
                                + "&authFailure=true&authFailureMsg=account.confirmation.pending", "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE,
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                                + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8)
                                + BasicAuthenticatorConstants.ERROR_CODE
                                + IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE
                                + BasicAuthenticatorConstants.AUTHENTICATORS
                                + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                                + BasicAuthenticatorConstants.LOCAL
                                + "&authFailure=true&authFailureMsg=password.reset.pending", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + ":dummyerrorcode",
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                                + BasicAuthenticatorConstants.AUTHENTICATORS
                                + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                                + BasicAuthenticatorConstants.LOCAL
                                + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                                + BasicAuthenticatorConstants.ERROR_CODE
                                + UserCoreConstants.ErrorCode.INVALID_CREDENTIAL
                                + BasicAuthenticatorConstants.FAILED_USERNAME +
                                URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8)
                                + "&remainingAttempts=" + 2, "3", "1"

                },
                {
                        UserCoreConstants.ErrorCode.INVALID_CREDENTIAL + ":",
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                                + BasicAuthenticatorConstants.AUTHENTICATORS
                                + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                                + BasicAuthenticatorConstants.LOCAL
                                + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                                + BasicAuthenticatorConstants.ERROR_CODE
                                + UserCoreConstants.ErrorCode.INVALID_CREDENTIAL
                                + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8)
                                + "&remainingAttempts=" + 2, "3", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST, DUMMY_LOGIN_PAGEURL + "?" +
                        DUMMY_QUERY_PARAMS + BasicAuthenticatorConstants.AUTHENTICATORS +
                        BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" + BasicAuthenticatorConstants.LOCAL +
                        "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message" +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(DUMMY_USER_NAME,
                        BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE, DUMMY_LOGIN_PAGEURL + "?"
                        + DUMMY_QUERY_PARAMS+ BasicAuthenticatorConstants.AUTHENTICATORS
                        + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":" + BasicAuthenticatorConstants.LOCAL
                        + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                        + BasicAuthenticatorConstants.ERROR_CODE
                        + IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE
                        + BasicAuthenticatorConstants.FAILED_USERNAME
                        + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE,
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS + BasicAuthenticatorConstants.FAILED_USERNAME +
                                URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE +
                                BasicAuthenticatorConstants.AUTHENTICATORS +
                                BasicAuthenticatorConstants.AUTHENTICATOR_NAME +
                                ":" + BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=login.fail.message", "1", "1"
                },
                {
                        "dummycode", DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS
                        + BasicAuthenticatorConstants.AUTHENTICATORS
                        + BasicAuthenticatorConstants.AUTHENTICATOR_NAME + ":"
                        + BasicAuthenticatorConstants.LOCAL
                        + "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message"
                        + BasicAuthenticatorConstants.ERROR_CODE + "dummycode"
                        + BasicAuthenticatorConstants.FAILED_USERNAME +
                        URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED, DUMMY_RETRY_URL_WITH_QUERY +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(DUMMY_USER_NAME,
                        BasicAuthenticatorConstants.UTF_8) + "&remainingAttempts=0", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":dummyReason", DUMMY_RETRY_URL_WITH_QUERY +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        "&lockedReason=dummyReason" + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode
                        (DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8) + "&remainingAttempts=0", "1", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED, DUMMY_RETRY_URL_WITH_QUERY +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(DUMMY_USER_NAME,
                        BasicAuthenticatorConstants.UTF_8), "4", "1"
                },
                {
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":dummyReason", DUMMY_RETRY_URL_WITH_QUERY +
                        BasicAuthenticatorConstants.ERROR_CODE + UserCoreConstants.ErrorCode.USER_IS_LOCKED +
                        "&lockedReason=dummyReason" + BasicAuthenticatorConstants.FAILED_USERNAME +
                        URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8), "4", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE,
                        "accountrecoveryendpoint/confirmrecovery.do?"
                                + BasicAuthenticatorConstants.USER_NAME_PARAM
                                + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8)
                                + BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM
                                + URLEncoder.encode(super_tenant, BasicAuthenticatorConstants.UTF_8)
                                + BasicAuthenticatorConstants.CONFIRMATION_PARAM
                                + URLEncoder.encode(DUMMY_PASSWORD, BasicAuthenticatorConstants.UTF_8)
                                + BasicAuthenticatorConstants.CALLBACK_PARAM
                                + URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE,
                        "accountrecoveryendpoint/confirmrecovery.do?" +
                                BasicAuthenticatorConstants.USER_NAME_PARAM +
                                URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM +
                                URLEncoder.encode(super_tenant, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(DUMMY_PASSWORD,
                                BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.CALLBACK_PARAM +
                                URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.REASON_PARAM +
                                URLEncoder.encode(RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name(),
                                        BasicAuthenticatorConstants.UTF_8), "1", "1"
                },
                {
                        IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE,
                        DUMMY_LOGIN_PAGEURL + "?" + DUMMY_QUERY_PARAMS + BasicAuthenticatorConstants.FAILED_USERNAME
                                + URLEncoder.encode(DUMMY_USER_NAME, BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE +
                                IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE +
                                BasicAuthenticatorConstants.AUTHENTICATORS + BasicAuthenticatorConstants.
                                AUTHENTICATOR_NAME + ":" + BasicAuthenticatorConstants.LOCAL +
                                "&authFailure=true&authFailureMsg=account.pending.approval", "1", "1"
                }
        };
    }

    @Test(dataProvider = "errorCodeProvider")
    public void initiateAuthenticationRequestTestcaseWithErrorCode(String errorCode, String expected, String maxLogin,
                                                                   String minLogin)
            throws AuthenticationFailedException, IOException, URISyntaxException {

        try (MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder = Mockito.mockStatic(
                FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade> configurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponent = Mockito.mockStatic(
                     IdentityCoreServiceComponent.class);
             MockedStatic<CarbonUtils> carbonUtils = Mockito.mockStatic(CarbonUtils.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<PrivilegedCarbonContext> privilegedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<ServerConfiguration> serverConfiguration = Mockito.mockStatic(ServerConfiguration.class)) {

            carbonUtils.when(CarbonUtils::getManagementTransport).thenReturn(DUMMY_PROTOCOL);
            serverConfiguration.when(ServerConfiguration::getInstance).thenReturn(mockServerConfiguration);
            when(mockServerConfiguration.getFirstProperty(IdentityCoreConstants.HOST_NAME)).thenReturn(DUMMY_HOSTNAME);
            identityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
            identityTenantUtil.when(IdentityTenantUtil::getTenantDomainFromContext).thenReturn("carbon.super");
            privilegedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(mockPrivilegedCarbonContext);
            when(mockPrivilegedCarbonContext.getTenantDomain()).thenReturn("carbon.super");
            identityCoreServiceComponent.when(IdentityCoreServiceComponent::getConfigurationContextService)
                    .thenReturn(mockConfigurationContextService);
            when(mockConfigurationContextService.getServerConfigContext()).thenReturn(mockConfigurationContext);
            carbonUtils.when(() -> CarbonUtils.getTransportProxyPort(eq(mockAxisConfiguration), anyString()))
                    .thenReturn(DUMMY_PORT);
            when(mockConfigurationContext.getAxisConfiguration()).thenReturn(mockAxisConfiguration);
            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockResponse.encodeRedirectURL(DUMMY_RETRY_URL + "?" + DUMMY_QUERY_PARAMS))
                    .thenReturn(DUMMY_RETRY_URL_WITH_QUERY);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);

            HashMap<String, String> paramMap = new HashMap<>();
            paramMap.put("showAuthFailureReason", "true");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("test", true, paramMap);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
            when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(DUMMY_PASSWORD);
            SequenceConfig conf = new SequenceConfig();
            conf.setApplicationConfig(applicationConfig);
            when(applicationConfig.isSaaSApp()).thenReturn(false);
            when((mockAuthnCtxt.getSequenceConfig())).thenReturn(conf);

            configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
            when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockConfigurationFacade.getAuthenticationEndpointRetryURL()).thenReturn(DUMMY_RETRY_URL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(true);

            when(mockIdentityErrorMsgContext.getErrorCode()).thenReturn(errorCode);
            when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(Integer.valueOf(maxLogin));
            when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(Integer.valueOf(minLogin));

            identityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(mockIdentityErrorMsgContext);

            doAnswer((Answer<Object>) invocation -> {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }).when(mockResponse).sendRedirect(anyString());

            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
            validateResponseParams(expected, redirect);
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

    @Test
    public void initiateAuthenticationRequestTestcaseWithUserNotFoundErrorCodeMasking()
            throws AuthenticationFailedException, IOException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade> configurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class)) {

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockResponse.encodeRedirectURL(DUMMY_RETRY_URL + "?" + DUMMY_QUERY_PARAMS))
                    .thenReturn(DUMMY_RETRY_URL_WITH_QUERY);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);

            HashMap<String, String> paramMap = new HashMap<>();
            paramMap.put("showAuthFailureReason", "true");
            paramMap.put("maskUserNotExistsErrorCode", "true");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("test", true, paramMap);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
            when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(DUMMY_PASSWORD);

            configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
            when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockConfigurationFacade.getAuthenticationEndpointRetryURL()).thenReturn(DUMMY_RETRY_URL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(true);

            when(mockIdentityErrorMsgContext.getErrorCode())
                    .thenReturn(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
            when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
            when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

            identityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(mockIdentityErrorMsgContext);

            doAnswer((Answer<Object>) invocation -> {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }).when(mockResponse).sendRedirect(anyString());

            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);
            if (StringUtils.contains(redirect,UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                Assert.fail("Response contains error code for USER_DOES_NOT_EXIST: "
                        + UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST + ". Response: " + redirect);
            }
        }
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

    @Test(dataProvider = "omitErrorParamsProvider")
    public void initiateAuthenticationRequestTestcaseWithOmittedErrorParams(String omittedParams)
            throws AuthenticationFailedException, IOException {

        try (MockedStatic<FileBasedConfigurationBuilder>
                     fileBasedConfigurationBuilder = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade> configurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class)) {

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockResponse.encodeRedirectURL(DUMMY_RETRY_URL + "?" + DUMMY_QUERY_PARAMS))
                    .thenReturn(DUMMY_RETRY_URL_WITH_QUERY);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);

            HashMap<String, String> paramMap = new HashMap<>();
            paramMap.put("showAuthFailureReason", "true");
            paramMap.put("errorParamsToOmit", omittedParams);
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("test", true, paramMap);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
            when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(DUMMY_PASSWORD);

            configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
            when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockConfigurationFacade.getAuthenticationEndpointRetryURL()).thenReturn(DUMMY_RETRY_URL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(true);

            when(mockIdentityErrorMsgContext.getErrorCode())
                    .thenReturn(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST);
            when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
            when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

            identityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(mockIdentityErrorMsgContext);

            doAnswer((Answer<Object>) invocation -> {

                redirect = (String) invocation.getArguments()[0];
                return null;
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
    }

    @Test
    public void initiateAuthenticationRequestTestcaseWithPasswordResetErrorOmitted()
            throws AuthenticationFailedException, IOException, URISyntaxException {

        try (MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder
                     = Mockito.mockStatic(FileBasedConfigurationBuilder.class);
             MockedStatic<ConfigurationFacade> configurationFacade = Mockito.mockStatic(ConfigurationFacade.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class)) {

            when(mockRequest.getParameter(BasicAuthenticatorConstants.USER_NAME)).thenReturn(DUMMY_USER_NAME);
            when(mockResponse.encodeRedirectURL(DUMMY_RETRY_URL + "?" + DUMMY_QUERY_PARAMS))
                    .thenReturn(DUMMY_RETRY_URL_WITH_QUERY);

            fileBasedConfigurationBuilder
                    .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);

            HashMap<String, String> paramMap = new HashMap<>();
            paramMap.put("maskAdminForcedPasswordResetErrorCode", "true");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig("test", true, paramMap);
            when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
            when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);
            when(mockAuthnCtxt.getProperty("PASSWORD_PROPERTY")).thenReturn(DUMMY_PASSWORD);

            configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
            when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
            when(mockConfigurationFacade.getAuthenticationEndpointRetryURL()).thenReturn(DUMMY_RETRY_URL);
            when(mockAuthnCtxt.isRetrying()).thenReturn(true);

            when(mockIdentityErrorMsgContext.getErrorCode())
                    .thenReturn(IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE);
            when(mockIdentityErrorMsgContext.getMaximumLoginAttempts()).thenReturn(1);
            when(mockIdentityErrorMsgContext.getFailedLoginAttempts()).thenReturn(1);

            identityUtil.when(IdentityUtil::getIdentityErrorMsg).thenReturn(mockIdentityErrorMsgContext);

            doAnswer((Answer<Object>) invocation -> {

                redirect = (String) invocation.getArguments()[0];
                return null;
            }).when(mockResponse).sendRedirect(anyString());

            basicAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockAuthnCtxt);

            validateResponseParam(BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM.replaceAll("&", ""), redirect,
                    "login.fail.message");
        }
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

    private void initiateAuthenticationRequest(
            MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder,
            MockedStatic<ConfigurationFacade> configurationFacade) throws IOException {

        fileBasedConfigurationBuilder
                .when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockFileBasedConfigurationBuilder);
        when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);

        doAnswer((Answer<Object>) invocation -> {

            isUserTenantDomainMismatch = (Boolean) invocation.getArguments()[1];
            return null;
        }).when(mockAuthnCtxt).setProperty(anyString(), anyBoolean());

        when(mockAuthnCtxt.getProperty("UserTenantDomainMismatch")).thenReturn(true);
        when(mockAuthnCtxt.getContextIdIncludedQueryParams()).thenReturn(DUMMY_QUERY_PARAMS);

        configurationFacade.when(ConfigurationFacade::getInstance).thenReturn(mockConfigurationFacade);
        when(mockConfigurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGEURL);
        when(mockAuthnCtxt.isRetrying()).thenReturn(true);

        doAnswer((Answer<Object>) invocation -> {

            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(mockResponse).sendRedirect(anyString());
    }
}
