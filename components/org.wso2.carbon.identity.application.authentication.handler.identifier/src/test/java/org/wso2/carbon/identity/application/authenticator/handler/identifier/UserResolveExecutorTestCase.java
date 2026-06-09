package org.wso2.carbon.identity.application.authenticator.handler.identifier;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.handler.identifier.UserResolveExecutor;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.flow.mgt.model.ExecutorDTO;
import org.wso2.carbon.identity.flow.mgt.model.MessageDTO;
import org.wso2.carbon.identity.flow.mgt.model.MessageDTO.MessageType;
import org.wso2.carbon.identity.flow.mgt.model.NodeConfig;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.config.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_RETRY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;

public class UserResolveExecutorTestCase {

    private static final String TEST_USERNAME = "testUser";
    private static final String TEST_TENANT_DOMAIN = "carbon.super";
    private static final int TEST_TENANT_ID = 1;
    private static final String TEST_DOMAIN = "PRIMARY";
    private static final String TEST_DOMAIN_QUALIFIED_USERNAME = TEST_DOMAIN + UserCoreConstants.DOMAIN_SEPARATOR + TEST_USERNAME;

    @Mock
    private FlowExecutionContext mockContext;

    @Mock
    private FlowUser mockFlowUser;

    @Mock
    private RealmService mockRealmService;

    @Mock
    private TenantManager mockTenantManager;

    @Mock
    private UserRealm mockUserRealm;

    @Mock
    private UserStoreManager mockUserStoreManager;

    @Mock
    private UserStoreManager mockSecondaryUserStoreManager;

    @Mock
    private RealmConfiguration mockRealmConfiguration;

    @Mock
    private MultiAttributeLoginService mockMultiAttributeLoginService;

    @Mock
    private NodeConfig mockNodeConfig;

    @Mock
    private ExecutorDTO mockExecutorDTO;

    private UserResolveExecutor userResolveExecutor;
    private final Map<String, Object> userClaims = new HashMap<>();
    private final Map<String, String> userInputData = new HashMap<>();
    private AutoCloseable closeable;
    private MockedStatic<IdentityUtil> identityUtilMock;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        userResolveExecutor = new UserResolveExecutor();

        // Mock IdentityUtil to return empty list for excluded user stores
        identityUtilMock = mockStatic(IdentityUtil.class);
        identityUtilMock.when(() -> IdentityUtil.getPropertyAsList(UserResolveExecutor.FLOW_EXECUTION_USER_STORE_DOMAIN))
                .thenReturn(new ArrayList<>());

        // Always disable multi-attribute login in all tests
        when(mockMultiAttributeLoginService.isEnabled(anyString())).thenReturn(false);
        setMockMultiAttributeLoginService();

        // Mock context setup
        when(mockContext.getFlowUser()).thenReturn(mockFlowUser);
        when(mockContext.getTenantDomain()).thenReturn(TEST_TENANT_DOMAIN);
        when(mockContext.getUserInputData()).thenReturn(userInputData);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(userClaims.get(FrameworkConstants.USERNAME_CLAIM));

        // Mock realm service setup
        setMockRealmService();

        // Mock user realm setup
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockTenantManager.getTenantId(TEST_TENANT_DOMAIN)).thenReturn(TEST_TENANT_ID);
        when(mockRealmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(mockUserRealm);
        when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);

        // Mock user store manager setup
        when(mockUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME))
                .thenReturn("PRIMARY");
        when(mockUserStoreManager.getSecondaryUserStoreManager()).thenReturn(mockSecondaryUserStoreManager);
        when(mockSecondaryUserStoreManager.getRealmConfiguration()).thenReturn(mockRealmConfiguration);
        when(mockRealmConfiguration.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME))
                .thenReturn(TEST_DOMAIN);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        userClaims.clear();
        userInputData.clear();
        if (identityUtilMock != null) {
            identityUtilMock.close();
        }
        closeable.close();
        resetMockRealmService();
        resetMockMultiAttributeLoginService();
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(userResolveExecutor.getName(), UserResolveExecutor.USER_RESOLVE_EXECUTOR);
    }

    @Test
    public void testExecuteWithNullUsername() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, null);
        ExecutorResponse response = userResolveExecutor.execute(mockContext);
        Assert.assertEquals(response.getResult(), STATUS_USER_INPUT_REQUIRED);
        verify(mockUserStoreManager, never()).getUserClaimValues(anyString(), any());
    }

    @Test
    public void testExecuteWithValidUsername() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(TEST_USERNAME)).thenReturn(false);
        when(mockUserStoreManager.isExistingUser("PRIMARY" + UserCoreConstants.DOMAIN_SEPARATOR + TEST_USERNAME)).thenReturn(true);

        Claim emailClaim = new Claim();
        emailClaim.setClaimUri("http://wso2.org/claims/emailaddress");
        emailClaim.setValue("test@example.com");

        Claim nameClaim = new Claim();
        nameClaim.setClaimUri("http://wso2.org/claims/givenname");
        nameClaim.setValue("Test User");

        Claim[] claims = new Claim[]{emailClaim, nameClaim};

        when(mockUserStoreManager.getUserClaimValues("PRIMARY" + UserCoreConstants.DOMAIN_SEPARATOR + TEST_USERNAME, null)).thenReturn(claims);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
        Assert.assertNotNull(response.getUpdatedUserClaims());
        Assert.assertEquals(response.getUpdatedUserClaims().get("http://wso2.org/claims/emailaddress"), "test@example.com");
        Assert.assertEquals(response.getUpdatedUserClaims().get("http://wso2.org/claims/givenname"), "Test User");
    }

    @Test
    public void testExecuteWithQualifiedUsername() throws Exception {

        String qualifiedUsername = TEST_DOMAIN_QUALIFIED_USERNAME;
        userClaims.put(FrameworkConstants.USERNAME_CLAIM, qualifiedUsername);

        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(qualifiedUsername);
        when(mockUserStoreManager.isExistingUser(qualifiedUsername)).thenReturn(false);
        when(mockUserStoreManager.isExistingUser("PRIMARY" + UserCoreConstants.DOMAIN_SEPARATOR + qualifiedUsername)).thenReturn(true);
        when(mockUserStoreManager.getUserClaimValues("PRIMARY" + UserCoreConstants.DOMAIN_SEPARATOR + qualifiedUsername, null)).thenReturn(new Claim[0]);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testResolveQualifiedUsernameInSecondaryUserStore() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(TEST_USERNAME)).thenReturn(false);
        when(mockUserStoreManager.isExistingUser("PRIMARY" + UserCoreConstants.DOMAIN_SEPARATOR + TEST_USERNAME)).thenReturn(false);
        when(mockUserStoreManager.getSecondaryUserStoreManager()).thenReturn(null); // No more secondary stores
        when(mockUserStoreManager.getUserClaimValues(TEST_USERNAME, null)).thenReturn(new Claim[0]);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testUserStoreException() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString())).thenThrow(new UserStoreException("Test exception"));

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_ERROR);
    }

    @Test
    public void testNullUserRealm() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockRealmService.getTenantUserRealm(TEST_TENANT_ID)).thenReturn(null);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_ERROR);
    }

    @Test
    public void testUserNotFound() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString()))
                .thenThrow(new UserStoreException("30007 - User does not exist"));

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testUserStoreExceptionWithErrorCode() throws Exception {

        userClaims.put(FrameworkConstants.USERNAME_CLAIM, TEST_USERNAME);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString()))
                .thenThrow(new UserStoreException("40001 - Some other error"));

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_ERROR);
        Assert.assertNotNull(response.getErrorMessage());
        Assert.assertTrue(response.getErrorMessage().contains("Error while resolving user"));
    }

    @Test
    public void testRollback() {

        ExecutorResponse response = userResolveExecutor.rollback(mockContext);
        Assert.assertNull(response);
    }

    private void setMockRealmService() throws Exception {

        Field field = IdentifierAuthenticatorServiceComponent.class.getDeclaredField("realmService");
        field.setAccessible(true);
        field.set(null, mockRealmService);
    }

    private void resetMockRealmService() throws Exception {

        Field field = IdentifierAuthenticatorServiceComponent.class.getDeclaredField("realmService");
        field.setAccessible(true);
        field.set(null, null);
    }

    private void setMockMultiAttributeLoginService() throws Exception {

        Field field = IdentifierAuthenticatorServiceComponent.class.getDeclaredField("multiAttributeLogin");
        field.setAccessible(true);
        field.set(null, mockMultiAttributeLoginService);
    }

    private void resetMockMultiAttributeLoginService() throws Exception {

        Field field = IdentifierAuthenticatorServiceComponent.class.getDeclaredField("multiAttributeLogin");
        field.setAccessible(true);
        field.set(null, null);
    }

    // Tests for notifying user existence.

    @Test
    public void testUserNotFound_withNotifyUserExistenceEnabled() throws Exception {

        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString()))
                .thenThrow(new UserStoreException("30007 - User does not exist"));
        setupExecutorMetadata("notifyUserExistence", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The user does not exist.", "{{user.not.found}}");
    }

    @Test
    public void testUserNotFound_withNotifyUserExistenceDisabled() throws Exception {

        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString()))
                .thenThrow(new UserStoreException("30007 - User does not exist"));
        setupExecutorMetadata("notifyUserExistence", "false");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testUserNotFound_withNullCurrentNode() throws Exception {

        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(anyString()))
                .thenThrow(new UserStoreException("30007 - User does not exist"));
        when(mockContext.getCurrentNode()).thenReturn(null);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    // Tests for resolving the user via a multi-attribute login identifier (e.g. mobile, email).

    @Test
    public void testMultiAttributeIdentifierNotFound_withNotifyUserExistenceEnabled() throws Exception {

        // Multi-attribute login enabled, an identifier supplied, but no user resolves for it.
        when(mockMultiAttributeLoginService.isEnabled(anyString())).thenReturn(true);
        when(mockMultiAttributeLoginService.resolveUser(anyString(), anyString()))
                .thenReturn(new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.FAIL));
        userInputData.put(UserResolveExecutor.USER_IDENTIFIER, "0771234567");
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(null);
        setupExecutorMetadata("notifyUserExistence", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The user does not exist.", "{{user.not.found}}");
    }

    @Test
    public void testMultiAttributeEnabledWithBlankIdentifier_returnsInputRequired() throws Exception {

        // Multi-attribute login enabled but no identifier supplied yet, so input is requested.
        when(mockMultiAttributeLoginService.isEnabled(anyString())).thenReturn(true);
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(null);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_USER_INPUT_REQUIRED);
        verify(mockMultiAttributeLoginService, never()).resolveUser(anyString(), anyString());
    }

    @Test
    public void testMultiAttributeIdentifierNotFound_withNotifyUserExistenceDisabled() throws Exception {

        when(mockMultiAttributeLoginService.isEnabled(anyString())).thenReturn(true);
        when(mockMultiAttributeLoginService.resolveUser(anyString(), anyString()))
                .thenReturn(new ResolvedUserResult(ResolvedUserResult.UserResolvedStatus.FAIL));
        userInputData.put(UserResolveExecutor.USER_IDENTIFIER, "0771234567");
        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(null);
        setupExecutorMetadata("notifyUserExistence", "false");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_USER_INPUT_REQUIRED);
    }

    // Tests for notifying user account status.

    @Test
    public void testAccountLocked_withNotifyAccountStatusEnabled() throws Exception {

        setupUserWithClaims(buildClaim(FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, "true"));
        setupExecutorMetadata("notifyUserAccountStatus", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The account is locked.", "{{account.locked}}");
    }

    @Test
    public void testAccountLocked_withMaxAttemptsExceededReason() throws Exception {

        setupUserWithClaims(
                buildClaim(FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, "true"),
                buildClaim(FrameworkConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, "MAX_ATTEMPTS_EXCEEDED"));
        setupExecutorMetadata("notifyUserAccountStatus", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The account is locked due to maximum failed login attempts.",
                "{{account.locked.max.attempts}}");
    }

    @Test
    public void testAccountLocked_withAdminInitiatedReason() throws Exception {

        setupUserWithClaims(
                buildClaim(FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, "true"),
                buildClaim(FrameworkConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, "ADMIN_INITIATED"));
        setupExecutorMetadata("notifyUserAccountStatus", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The account has been locked by an administrator.",
                "{{account.locked.admin.initiated}}");
    }

    @Test
    public void testAccountDisabled_withNotifyAccountStatusEnabled() throws Exception {

        setupUserWithClaims(buildClaim(FrameworkConstants.ACCOUNT_DISABLED_CLAIM_URI, "true"));
        setupExecutorMetadata("notifyUserAccountStatus", "true");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_RETRY);
        assertSingleErrorMessage(response, "The account is disabled.", "{{account.disabled}}");
    }

    @Test
    public void testAccountLocked_withNotifyAccountStatusDisabled() throws Exception {

        setupUserWithClaims(buildClaim(FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, "true"));
        setupExecutorMetadata("notifyUserAccountStatus", "false");

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    @Test
    public void testAccountStatus_withNullCurrentNode() throws Exception {

        setupUserWithClaims(buildClaim(FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, "true"));
        when(mockContext.getCurrentNode()).thenReturn(null);

        ExecutorResponse response = userResolveExecutor.execute(mockContext);

        Assert.assertEquals(response.getResult(), STATUS_COMPLETE);
    }

    // Helper methods.

    private void setupExecutorMetadata(String key, String value) {

        Map<String, String> metadata = new HashMap<>();
        metadata.put(key, value);
        when(mockContext.getCurrentNode()).thenReturn(mockNodeConfig);
        when(mockNodeConfig.getExecutorConfig()).thenReturn(mockExecutorDTO);
        when(mockExecutorDTO.getMetadata()).thenReturn(metadata);
    }

    private void setupUserWithClaims(Claim... additionalClaims) throws Exception {

        when(mockFlowUser.getClaim(FrameworkConstants.USERNAME_CLAIM)).thenReturn(TEST_USERNAME);
        when(mockUserStoreManager.isExistingUser(TEST_DOMAIN_QUALIFIED_USERNAME)).thenReturn(true);
        Claim emailClaim = buildClaim("http://wso2.org/claims/emailaddress", "test@example.com");
        Claim[] allClaims = new Claim[1 + additionalClaims.length];
        allClaims[0] = emailClaim;
        System.arraycopy(additionalClaims, 0, allClaims, 1, additionalClaims.length);
        when(mockUserStoreManager.getUserClaimValues(TEST_DOMAIN_QUALIFIED_USERNAME, null))
                .thenReturn(allClaims);
    }

    private void assertSingleErrorMessage(ExecutorResponse response, String expectedMessage, String expectedI18nKey) {

        Assert.assertNotNull(response.getMessages());
        Assert.assertEquals(response.getMessages().size(), 1);
        MessageDTO message = response.getMessages().get(0);
        Assert.assertEquals(message.getType(), MessageType.ERROR);
        Assert.assertEquals(message.getMessage(), expectedMessage);
        Assert.assertEquals(message.getI18nKey(), expectedI18nKey);
    }

    private Claim buildClaim(String uri, String value) {

        Claim claim = new Claim();
        claim.setClaimUri(uri);
        claim.setValue(value);
        return claim;
    }
}
