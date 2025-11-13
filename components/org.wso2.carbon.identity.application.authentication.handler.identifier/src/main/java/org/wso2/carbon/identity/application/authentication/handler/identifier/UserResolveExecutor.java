/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authentication.handler.identifier;

import java.util.Arrays;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_ERROR;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * This class is responsible for resolving user.
 */
public class UserResolveExecutor implements Executor {

    public static final String USER_RESOLVE_EXECUTOR = "UserResolveExecutor";
    public static final String USER_IDENTIFIER = "userIdentifier";
    private static final Log log = LogFactory.getLog(UserResolveExecutor.class);
    public static final String FLOW_EXECUTION_USER_STORE_DOMAIN = "FlowExecution.ExcludedUserstores.Userstore";

    /**
     * Returns the name of the executor.
     *
     * @return Name of the executor.
     */
    @Override
    public String getName() {

        return USER_RESOLVE_EXECUTOR;
    }

    /**
     * Returns the list of claims required to initiate the flow.
     *
     * @return List of claim URIs required for initiation.
     */
    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (IdentifierAuthenticatorServiceComponent.getMultiAttributeLogin().isEnabled(tenantDomain)) {
            initiationData.add(USER_IDENTIFIER);
        }
        initiationData.add(USERNAME_CLAIM_URI);
        return initiationData;
    }

    /**
     * Executes the user resolution logic. If the username claim is not present, signals that user input is required.
     * Otherwise, resolves user attributes and adds them to the flow context.
     *
     * @param context Flow execution context.
     * @return ExecutorResponse indicating the status of execution.
     */
    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        String usernameClaim = resolveUsernameClaim(context);
        if (usernameClaim == null) {
            return new ExecutorResponse(STATUS_USER_INPUT_REQUIRED);
        }
        return resolveUser(usernameClaim, context.getTenantDomain(), context);
    }

    /**
     * Rollback logic for the executor. Not implemented.
     *
     * @param flowExecutionContext Flow execution context.
     * @return Always returns null.
     */
    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) {

        return null;
    }

    /**
     * Resolves user attributes and adds them to the flow context.
     *
     * @param username     Username to resolve.
     * @param tenantDomain Tenant domain.
     * @param context      Flow execution context.
     */
    private ExecutorResponse resolveUser(String username, String tenantDomain, FlowExecutionContext context) {

        ExecutorResponse executorResponse = new ExecutorResponse();
        try {
            UserRealm userRealm = getUserRealm(tenantDomain);
            if (userRealm == null) {
                executorResponse.setResult(STATUS_ERROR);
                executorResponse.setErrorMessage("User realm is not available for tenant: " + tenantDomain);
                return executorResponse;
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            String resolvedUsername = resolveQualifiedUsername(username, userStoreManager, context);
            Claim[] claims = userStoreManager.getUserClaimValues(resolvedUsername, null);
            if (claims != null && claims.length > 0) {
                Map<String, String> claimMap = Arrays.stream(claims)
                        .filter(c -> c != null && c.getClaimUri() != null)
                        .collect(Collectors.toMap(Claim::getClaimUri, Claim::getValue));
                context.getFlowUser().addClaims(claimMap);
            }
            executorResponse.setResult(STATUS_COMPLETE);

        } catch (UserStoreException e) {
            if (e.getMessage().startsWith(String.valueOf(30007))) {
                if (log.isDebugEnabled()) {
                    log.debug("User '" + LoggerUtils.getMaskedContent(username) + "' does not exist in tenant '" +
                            tenantDomain + "'.");
                }
                executorResponse.setResult(STATUS_COMPLETE);
            } else {
                executorResponse.setResult(STATUS_ERROR);
                executorResponse.setErrorMessage("Error while resolving user '" +
                        LoggerUtils.getMaskedContent(username) + "' in tenant '" + tenantDomain + "': " + e.getMessage());
            }
        }
        return executorResponse;
    }

    /**
     * Retrieves the user realm for the given tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm instance for the tenant.
     * @throws UserStoreException If an error occurs while retrieving the user realm.
     */
    private UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        RealmService realmService = IdentifierAuthenticatorServiceComponent.getRealmService();
        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        return (UserRealm) realmService.getTenantUserRealm(tenantId);
    }

    /**
     * Resolves the alternative login username if multi-attribute login is enabled.
     *
     * @param context Flow execution context.
     * @return Username if resolved, otherwise null.
     */
    private String resolveUsernameFromUserIdentifier(FlowExecutionContext context) {

        String userIdentifier = context.getUserInputData().get(USER_IDENTIFIER);
        ResolvedUserResult resolvedResult = IdentifierAuthenticatorServiceComponent
                .getMultiAttributeLogin()
                .resolveUser(userIdentifier, context.getTenantDomain());

        if (ResolvedUserResult.UserResolvedStatus.SUCCESS.equals(resolvedResult.getResolvedStatus())) {
            return resolvedResult.getUser().getUsername();
        }

        return null;
    }

    /**
     * Resolves the fully qualified username by checking all user stores.
     *
     * @param username         Username to resolve.
     * @param userStoreManager User store manager.
     * @return Fully qualified username if found, otherwise the original username.
     * @throws UserStoreException If an error occurs while accessing the user store.
     */
    private String resolveQualifiedUsername(String username, UserStoreManager userStoreManager,
                                            FlowExecutionContext context)
            throws UserStoreException {

        List<String> excludedUserStores = IdentityUtil.getPropertyAsList(FLOW_EXECUTION_USER_STORE_DOMAIN);

        while (userStoreManager != null) {
            String domain = userStoreManager.getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

            boolean isReadOnly = Boolean.parseBoolean(userStoreManager.getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_READ_ONLY));

            if (StringUtils.isNotBlank(domain)) {
                // Skip this user store if it's read-only or included in the excluded user store list.
                if (isReadOnly || excludedUserStores.contains(domain)) {
                    userStoreManager = userStoreManager.getSecondaryUserStoreManager();
                    continue;
                }

                String domainQualifiedUsername = domain + UserCoreConstants.DOMAIN_SEPARATOR + username;
                if (userStoreManager.isExistingUser(domainQualifiedUsername)) {
                    context.getFlowUser().setUserStoreDomain(domain);
                    return domainQualifiedUsername;
                }
            }
            userStoreManager = userStoreManager.getSecondaryUserStoreManager();
        }
        // If no user found in any user store, return the original username.
        return username;
    }

    /**
     * Resolves the username claim from the flow context.
     *
     * @param context Flow execution context.
     * @return Username claim if resolved, otherwise null.
     */
    private String resolveUsernameClaim(FlowExecutionContext context) {

        String usernameClaim = null;
        if (IdentifierAuthenticatorServiceComponent.getMultiAttributeLogin().isEnabled(context.getTenantDomain())) {
            usernameClaim = resolveUsernameFromUserIdentifier(context);
        }
        if (StringUtils.isBlank(usernameClaim)) {
            usernameClaim = (String) context.getFlowUser().getClaim(FrameworkConstants.USERNAME_CLAIM);
        }
        return usernameClaim;
    }
}
