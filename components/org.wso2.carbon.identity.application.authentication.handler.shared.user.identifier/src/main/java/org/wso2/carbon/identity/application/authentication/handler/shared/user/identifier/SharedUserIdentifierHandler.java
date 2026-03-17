/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal.SharedUserIdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.BasicAuthUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.ErrorMessages;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.AUTHENTICATOR_SHARED_USER_IDENTIFIER;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.INITIATE_SHARED_USER_IDENTIFIER_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.LogConstants.SHARED_USER_IDENTIFIER_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.USER_NAME;
import static org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandlerConstants.USERNAME_USER_INPUT;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.DISPLAY_USER_NAME;

/**
 * Shared user identifier based handler.
 * <p>
 * This handler is responsible for taking a user identifier input and checking if the user is a shared user
 * in the specific tenant. It extends {@link AbstractApplicationAuthenticator} and implements
 * {@link AuthenticationFlowHandler}.
 * </p>
 */
public class SharedUserIdentifierHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final long serialVersionUID = 4438354156955223654L;
    private static final Log log = LogFactory.getLog(SharedUserIdentifierHandler.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String userName = request.getParameter(USER_NAME);
        boolean canHandle = userName != null;
        if (LoggerUtils.isDiagnosticLogsEnabled() && canHandle) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE,
                    FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("Shared User Identifier Handler is handling the request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, INITIATE_SHARED_USER_IDENTIFIER_AUTH_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating shared user identifier first authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = context.getContextIdIncludedQueryParams();

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=username.fail.message";
            }

            String redirectURL = loginPage + ("?" + queryParams)
                    + SharedUserIdentifierHandlerConstants.AUTHENTICATORS + getName() + ":"
                    + SharedUserIdentifierHandlerConstants.LOCAL + retryParam;
            response.sendRedirect(redirectURL);
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                    e.getMessage(), User.getUserFromUserName(request.getParameter(USER_NAME)), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        DiagnosticLog.DiagnosticLogBuilder authProcessCompletedDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing shared user identifier first authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);

            authProcessCompletedDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SHARED_USER_IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            authProcessCompletedDiagnosticLogBuilder.inputParams(getApplicationDetails(context))
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep());
        }

        String identifierFromRequest = request.getParameter(USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new InvalidCredentialsException(ErrorMessages.EMPTY_USERNAME.getCode(),
                    ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        context.setProperty(USERNAME_USER_INPUT, identifierFromRequest);

        String username = identifierFromRequest;
//        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
//            FrameworkUtils.validateUsername(identifierFromRequest, context);
//            username = FrameworkUtils.preprocessUsername(identifierFromRequest, context);
//        }

//        String tenantDomain = getTenantDomainFromUserName(context,
//                BasicAuthUtil.usePreprocessedUsername(context) ? username : identifierFromRequest);
//        String tenantAwareUsername = BasicAuthUtil.getTenantAwareUsername(context,
//                BasicAuthUtil.usePreprocessedUsername(context) ? username : identifierFromRequest);
        String tenantDomain = context.getTenantDomain();
        String userId = null;
        String userStoreDomain =  IdentityUtil.extractDomainFromName(username);

        // Resolve user via multi-attribute login if enabled.
//        if (SharedUserIdentifierAuthenticatorServiceComponent.getMultiAttributeLogin()
//                .isEnabled(context.getTenantDomain())) {
//            ResolvedUserResult resolvedUserResult = SharedUserIdentifierAuthenticatorServiceComponent
//                    .getMultiAttributeLogin().resolveUser(username, tenantDomain);
//            if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.
//                    equals(resolvedUserResult.getResolvedStatus())) {
//                tenantAwareUsername = resolvedUserResult.getUser().getUsername();
//                username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
//                userId = resolvedUserResult.getUser().getUserID();
//                userStoreDomain = resolvedUserResult.getUser().getUserStoreDomain();
//            }
//        }

//        // Resolve user ID from user store if not already resolved.
//        if (userId == null) {
//            userId = resolveUserIdFromUserStore(tenantDomain, tenantAwareUsername, username);
//        }
        userId = resolveUserIdFromUserStore(tenantDomain, username);

        // Check if the user is a shared user using OrganizationUserSharingService.
        resolveSharedUser(userId, tenantDomain, username, userStoreDomain, context);

//        Map<String, Object> authProperties = context.getProperties();
//        if (authProperties == null) {
//            authProperties = new HashMap<>();
//            context.setProperties(authProperties);
//        }

        // To autopopulate at later steps.
        persistUsername(context, username);

        if (LoggerUtils.isDiagnosticLogsEnabled() && authProcessCompletedDiagnosticLogBuilder != null) {
            authProcessCompletedDiagnosticLogBuilder
                    .resultMessage("Shared user identifier first authentication successful.")
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(username) : username)
                    .inputParam("user store domain", userStoreDomain)
                    .inputParam(LogConstants.InputKeys.USER_ID, userId);
            LoggerUtils.triggerDiagnosticLogEvent(authProcessCompletedDiagnosticLogBuilder);
        }
    }

    /**
     * Resolves the user ID from the user store for the given tenant domain and username.
     *
     * @param tenantDomain       The tenant domain.
     * @param tenantAwareUsername The tenant aware username.
     * @return The resolved user ID.
     * @throws AuthenticationFailedException If user resolution fails.
     */
    private String resolveUserIdFromUserStore(String tenantDomain, String tenantAwareUsername)
            throws AuthenticationFailedException {

        try {
            int tenantId = SharedUserIdentifierAuthenticatorServiceComponent
                    .getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = SharedUserIdentifierAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm == null) {
                throw new AuthenticationFailedException(
                        ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getCode(),
                        String.format(ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getMessage(),
                                tenantId), User.getUserFromUserName(tenantAwareUsername));
            }

            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            String userId = userStoreManager.getUserIDFromUserName(tenantAwareUsername);

            if (userId == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User does not exist in tenant: " + tenantDomain);
                }
                throw new InvalidCredentialsException(ErrorMessages.USER_DOES_NOT_EXIST.getCode(),
                        ErrorMessages.USER_DOES_NOT_EXIST.getMessage(), User.getUserFromUserName(tenantAwareUsername));
            }
            return userId;
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("SharedUserIdentifierHandler failed while trying to get the tenant ID of the user "
                        + tenantAwareUsername, e);
            }
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TENANT_ID_OF_THE_USER.getCode(),
                    e.getMessage(), User.getUserFromUserName(tenantAwareUsername), e);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("SharedUserIdentifierHandler failed while trying to authenticate.", e);
            }
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(),
                    e.getMessage(), User.getUserFromUserName(tenantAwareUsername), e);
        }
    }

    /**
     * Validates whether the given user is a shared user in the current tenant by checking
     * the user association using the {@link OrganizationUserSharingService}.
     *
     * @param userId       The user ID.
     * @param tenantDomain The tenant domain.
     * @param username     The full username (used for error context).
     * @throws AuthenticationFailedException If the user is not a shared user or an error occurs.
     */
    private void resolveSharedUser(String userId, String tenantDomain, String username, String userStoreDomain,
                                   AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OrganizationManager organizationManager = SharedUserIdentifierAuthenticatorServiceComponent
                    .getOrganizationManager();
            String organizationId = organizationManager.resolveOrganizationId(tenantDomain);

            if (StringUtils.isBlank(organizationId)) {
                throw new AuthenticationFailedException(ErrorMessages.ORGANIZATION_MGT_EXCEPTION.getCode(),
                        "Unable to resolve organization ID for tenant: " + tenantDomain,
                        User.getUserFromUserName(username));
            }

            OrganizationUserSharingService userSharingService = SharedUserIdentifierAuthenticatorServiceComponent
                    .getOrganizationUserSharingService();
            UserAssociation userAssociation = userSharingService.getUserAssociation(userId, organizationId);

            if (userAssociation == null) {
                if (log.isDebugEnabled()) {
                    log.debug("User with ID: " + userId + " is not a shared user in organization: "
                            + organizationId);
                }
                throw new AuthenticationFailedException(ErrorMessages.USER_NOT_A_SHARED_USER.getCode(),
                        ErrorMessages.USER_NOT_A_SHARED_USER.getMessage(), User.getUserFromUserName(username));
            }

            if (log.isDebugEnabled()) {
                log.debug("User with ID: " + userId + " is confirmed as a shared user in organization: "
                        + organizationId + " (associated user ID: " + userAssociation.getAssociatedUserId()
                        + ", resident org: " + userAssociation.getUserResidentOrganizationId() + ")");
            }

            AuthenticatedUser user = new AuthenticatedUser();
            user.setUserName(username);
            user.setUserStoreDomain(userStoreDomain);
            user.setUserResidentOrganization(userAssociation.getUserResidentOrganizationId());
            user.setAccessingOrganization(organizationManager.resolveOrganizationId(context.getTenantDomain()));
            user.setTenantDomain(organizationManager.resolveTenantDomain(
                    userAssociation.getUserResidentOrganizationId()));
            user.setSharedUser(true);
            context.setSubject(user);
        } catch (OrganizationManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("SharedUserIdentifierHandler failed while checking shared user status.", e);
            }
            throw new AuthenticationFailedException(ErrorMessages.ORGANIZATION_MGT_EXCEPTION.getCode(),
                    e.getMessage(), User.getUserFromUserName(username), e);
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {

        return SharedUserIdentifierHandlerConstants.HANDLER_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return SharedUserIdentifierHandlerConstants.HANDLER_NAME;
    }

    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
    }

    /**
     * Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME, applicationName));
        return applicationDetailsMap;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(BasicAuthenticatorConstants.USER_NAME);
        authenticatorData.setRequiredParams(requiredParams);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USER_NAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, BasicAuthenticatorConstants.USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);

        return Optional.of(authenticatorData);
    }

    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_SHARED_USER_IDENTIFIER;
    }

    /**
     * Resolves the tenant domain from the username based on the server configuration.
     *
     * @param context  The authentication context containing application configuration.
     * @param username The username from which to extract the tenant domain.
     * @return The resolved tenant domain.
     */
    private String getTenantDomainFromUserName(AuthenticationContext context, String username) {

        if (Boolean.parseBoolean(IdentityUtil.getProperty(
                BasicAuthUtil.RESOLVE_TENANT_DOMAIN_FROM_USERNAME_CONFIG))) {
            return MultitenantUtils.getTenantDomain(username);
        }

        boolean isSaaSApp = context.getSequenceConfig().getApplicationConfig().isSaaSApp();
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && !isSaaSApp) {
            return IdentityTenantUtil.getTenantDomainFromContext();
        }
        return MultitenantUtils.getTenantDomain(username);
    }
}

