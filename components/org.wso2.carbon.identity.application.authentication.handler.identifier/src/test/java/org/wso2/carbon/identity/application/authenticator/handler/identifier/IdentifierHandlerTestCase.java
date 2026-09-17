/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.handler.identifier;

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandler;
import org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.JSAttributes.JS_IDENTIFIER_FIRST_USER_INPUT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.USERNAME_USER_INPUT;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.USER_NAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.DISPLAY_USER_NAME;

/**
 * Unit test cases for the Identifier-first Authenticator.
 */
public class IdentifierHandlerTestCase {

    private static final String SKIP_IDENTIFIER_PRE_PROCESS = "skipIdentifierPreProcess";
    private static final String IDENTIFIER = "alice@example.com";
    private static final String RESOLVED_USERNAME = "alice";
    private static final String RESOLVED_USER_ID = "3f1c2a7e-6b0d-4a52-9d6e-1e2f3a4b5c6d";
    private static final String PRIMARY_DOMAIN = "PRIMARY";
    private static final String SUPER_TENANT_DOMAIN = "carbon.super";

    private AuthenticationContext mockAuthnCtxt;
    private ExternalIdPConfig externalIdPConfig;
    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;
    private SequenceConfig mockSequenceConfig;
    private ApplicationConfig mockApplicationConfig;
    private MultiAttributeLoginService mockMultiAttributeLoginService;
    private FileBasedConfigurationBuilder mockFileBasedConfigurationBuilder;
    private MockedStatic<IdentityTenantUtil> mockIdentityTenantUtil;
    private MockedStatic<LoggerUtils> mockLoggerUtils;
    private MockedStatic<IdentityUtil> mockIdentityUtil;
    private MockedStatic<MultitenantUtils> mockMultitenantUtils;
    private MockedStatic<FileBasedConfigurationBuilder> fileBasedConfigurationBuilder;

    private final IdentifierHandler identifierHandler = new IdentifierHandler();

    @BeforeTest
    public void setup() {

        System.setProperty("carbon.config.dir.path", "carbon.home");
    }


    @BeforeMethod
    public void init() throws Exception {

        mockAuthnCtxt = mock(AuthenticationContext.class);
        externalIdPConfig = mock(ExternalIdPConfig.class);
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockSequenceConfig = mock(SequenceConfig.class);
        mockApplicationConfig = mock(ApplicationConfig.class);
        mockMultiAttributeLoginService = mock(MultiAttributeLoginService.class);
        mockFileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);

        when(mockSequenceConfig.getApplicationConfig()).thenReturn(mockApplicationConfig);
        when(mockApplicationConfig.isSaaSApp()).thenReturn(false);
        when(mockMultiAttributeLoginService.isEnabled(anyString())).thenReturn(false);
        setMultiAttributeLoginService(mockMultiAttributeLoginService);

        mockIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(false);
        mockLoggerUtils = mockStatic(LoggerUtils.class);
        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        mockIdentityUtil = mockStatic(IdentityUtil.class);
        mockIdentityUtil.when(IdentityUtil::isEmailUsernameValidationDisabled).thenReturn(true);
        mockMultitenantUtils = mockStatic(MultitenantUtils.class);
        mockMultitenantUtils.when(() -> MultitenantUtils.getTenantDomain(anyString()))
                .thenReturn(SUPER_TENANT_DOMAIN);
        mockMultitenantUtils.when(() -> MultitenantUtils.getTenantAwareUsername(anyString()))
                .thenAnswer(invocation -> invocation.getArgument(0));
        fileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        fileBasedConfigurationBuilder.when(FileBasedConfigurationBuilder::getInstance)
                .thenReturn(mockFileBasedConfigurationBuilder);
        when(mockFileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(null);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        fileBasedConfigurationBuilder.close();
        mockMultitenantUtils.close();
        mockIdentityUtil.close();
        mockLoggerUtils.close();
        mockIdentityTenantUtil.close();
        setMultiAttributeLoginService(null);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = identifierHandler.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(mockAuthnCtxt.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("LOCAL");
        Optional<AuthenticatorData> authenticatorData = identifierHandler.getAuthInitiationData(mockAuthnCtxt);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USER_NAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, BasicAuthenticatorConstants.USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);

        Assert.assertEquals(authenticatorDataObj.getDisplayName(), IdentifierHandlerConstants.HANDLER_FRIENDLY_NAME);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(), 1);
        Assert.assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);

            Assert.assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            Assert.assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            Assert.assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            Assert.assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter mandatory status should match.");
        }
    }

    @Test
    public void processAuthenticationResponsePersistsIdentifierWhenPreProcessingIsSkipped() throws Exception {

        AuthenticationContext context = buildAuthenticationContext();
        Map<String, String> handlerParams = new HashMap<>();
        handlerParams.put(SKIP_IDENTIFIER_PRE_PROCESS, "true");
        Map<String, Map<String, String>> runtimeParams = new HashMap<>();
        runtimeParams.put(IdentifierHandlerConstants.HANDLER_NAME, handlerParams);
        context.addAuthenticatorParams(runtimeParams);
        when(mockRequest.getParameter(USER_NAME)).thenReturn(IDENTIFIER);

        processAuthenticationResponse(context);

        // Without pre-processing, the identifier is both the username and the value shown on the login page.
        Map<String, String> commonParams = context.getAuthenticatorParams(JS_COMMON_OPTIONS);
        Assert.assertEquals(commonParams.get(JS_OPTIONS_USERNAME), IDENTIFIER);
        Assert.assertEquals(commonParams.get(JS_IDENTIFIER_FIRST_USER_INPUT), IDENTIFIER);
        Assert.assertEquals(context.getSubject().getUserName(), IDENTIFIER);
        Assert.assertEquals(context.getProperty(USERNAME_USER_INPUT), IDENTIFIER);
    }

    @Test
    public void processAuthenticationResponsePersistsIdentifierAsUsernameWhenConfigured() throws Exception {

        mockIdentityUtil.when(() -> IdentityUtil.getProperty(IdentityConstants.ServerConfig.IDENTIFIER_AS_USERNAME))
                .thenReturn("true");
        AuthenticationContext context = buildAuthenticationContext();
        resolveUserFromIdentifier();
        when(mockRequest.getParameter(USER_NAME)).thenReturn(IDENTIFIER);

        processAuthenticationResponse(context);

        // The identifier is persisted as the username although the user was resolved to a different username.
        Map<String, String> commonParams = context.getAuthenticatorParams(JS_COMMON_OPTIONS);
        Assert.assertEquals(commonParams.get(JS_OPTIONS_USERNAME), IDENTIFIER);
        Assert.assertEquals(commonParams.get(JS_IDENTIFIER_FIRST_USER_INPUT), IDENTIFIER);
        Assert.assertEquals(context.getSubject().getUserName(), RESOLVED_USERNAME);
        Assert.assertEquals(context.getSubject().getUserId(), RESOLVED_USER_ID);
    }

    @Test
    public void processAuthenticationResponsePersistsTenantAwareUsernameForTenantQualifiedUrls() throws Exception {

        mockIdentityTenantUtil.when(IdentityTenantUtil::isTenantQualifiedUrlsEnabled).thenReturn(true);
        AuthenticationContext context = buildAuthenticationContext();
        resolveUserFromIdentifier();
        when(mockRequest.getParameter(USER_NAME)).thenReturn(IDENTIFIER);

        processAuthenticationResponse(context);

        // The resolved, tenant aware username is persisted next to the identifier the user typed.
        Map<String, String> commonParams = context.getAuthenticatorParams(JS_COMMON_OPTIONS);
        Assert.assertEquals(commonParams.get(JS_OPTIONS_USERNAME), RESOLVED_USERNAME);
        Assert.assertEquals(commonParams.get(JS_IDENTIFIER_FIRST_USER_INPUT), IDENTIFIER);
        Assert.assertEquals(context.getSubject().getUserName(), RESOLVED_USERNAME);
        Assert.assertEquals(context.getSubject().getTenantDomain(), SUPER_TENANT_DOMAIN);
        Assert.assertEquals(context.getSubject().getUserStoreDomain(), PRIMARY_DOMAIN);
    }

    @Test
    public void processAuthenticationResponsePersistsPreprocessedUsername() throws Exception {

        AuthenticationContext context = buildAuthenticationContext();
        resolveUserFromIdentifier();
        when(mockRequest.getParameter(USER_NAME)).thenReturn(IDENTIFIER);

        processAuthenticationResponse(context);

        // The resolved, tenant qualified username is persisted next to the identifier the user typed.
        Map<String, String> commonParams = context.getAuthenticatorParams(JS_COMMON_OPTIONS);
        Assert.assertEquals(commonParams.get(JS_OPTIONS_USERNAME), RESOLVED_USERNAME + "@" + SUPER_TENANT_DOMAIN);
        Assert.assertEquals(commonParams.get(JS_IDENTIFIER_FIRST_USER_INPUT), IDENTIFIER);
        Assert.assertEquals(context.getSubject().getUserName(), RESOLVED_USERNAME);
        Assert.assertEquals(context.getProperty(USERNAME_USER_INPUT), IDENTIFIER);
    }

    @DataProvider(name = "blankIdentifierFirstUserInputs")
    public Object[][] blankIdentifierFirstUserInputs() {

        return new Object[][]{{null}, {""}, {"   "}};
    }

    @Test(dataProvider = "blankIdentifierFirstUserInputs")
    public void persistUsernameOmitsBlankIdentifierFirstUserInput(String identifierFirstUserInput) throws Exception {

        // The response processing rejects a blank identifier before anything is persisted, so the blank case is
        // only reachable through the persisting method itself.
        AuthenticationContext context = buildAuthenticationContext();
        Method persistUsername = IdentifierHandler.class.getDeclaredMethod("persistUsername",
                AuthenticationContext.class, String.class, String.class);
        persistUsername.setAccessible(true);

        persistUsername.invoke(identifierHandler, context, RESOLVED_USERNAME, identifierFirstUserInput);

        Map<String, String> commonParams = context.getAuthenticatorParams(JS_COMMON_OPTIONS);
        Assert.assertEquals(commonParams.get(JS_OPTIONS_USERNAME), RESOLVED_USERNAME);
        Assert.assertFalse(commonParams.containsKey(JS_IDENTIFIER_FIRST_USER_INPUT));
    }

    private AuthenticationContext buildAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SUPER_TENANT_DOMAIN);
        context.setSequenceConfig(mockSequenceConfig);
        return context;
    }

    /**
     * Let multi attribute login resolve the identifier the user typed to the username of an existing user.
     */
    private void resolveUserFromIdentifier() {

        User resolvedUser = new User();
        resolvedUser.setUserID(RESOLVED_USER_ID);
        resolvedUser.setUsername(RESOLVED_USERNAME);
        resolvedUser.setUserStoreDomain(PRIMARY_DOMAIN);
        resolvedUser.setTenantDomain(SUPER_TENANT_DOMAIN);
        ResolvedUserResult resolvedUserResult =
                new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.SUCCESS);
        resolvedUserResult.setUser(resolvedUser);
        when(mockMultiAttributeLoginService.isEnabled(SUPER_TENANT_DOMAIN)).thenReturn(true);
        when(mockMultiAttributeLoginService.resolveUser(IDENTIFIER, SUPER_TENANT_DOMAIN))
                .thenReturn(resolvedUserResult);
    }

    private void processAuthenticationResponse(AuthenticationContext context) throws Exception {

        Method processAuthenticationResponse = IdentifierHandler.class.getDeclaredMethod(
                "processAuthenticationResponse", HttpServletRequest.class, HttpServletResponse.class,
                AuthenticationContext.class);
        processAuthenticationResponse.setAccessible(true);
        try {
            processAuthenticationResponse.invoke(identifierHandler, mockRequest, mockResponse, context);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    private static void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService)
            throws Exception {

        Field field = IdentifierAuthenticatorServiceComponent.class.getDeclaredField("multiAttributeLogin");
        field.setAccessible(true);
        field.set(null, multiAttributeLoginService);
    }
}
