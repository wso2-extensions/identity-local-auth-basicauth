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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

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
    private static final Log log = LogFactory.getLog(UserResolveExecutor.class);

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
        initiationData.add(USERNAME_CLAIM_URI);
        return initiationData;
    }

    /**
     * Executes the user resolution logic. If the username claim is not present, signals that user input is required.
     * Otherwise, resolves user attributes and adds them to the flow context.
     *
     * @param context Flow execution context.
     * @return ExecutorResponse indicating the status of execution.
     * @throws FlowEngineException If an error occurs during execution.
     */
    @Override
    public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

        ExecutorResponse executorResponse;
        String usernameClaim = (String) context.getFlowUser().getClaim(FrameworkConstants.USERNAME_CLAIM);
        if (usernameClaim == null) {
            executorResponse = new ExecutorResponse(STATUS_USER_INPUT_REQUIRED);
        } else {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(usernameClaim);
            executorResponse = resolveUser(tenantAwareUsername, context.getTenantDomain(), context);
        }
        return executorResponse;
    }

    /**
     * Rollback logic for the executor. Not implemented.
     *
     * @param flowExecutionContext Flow execution context.
     * @return Always returns null.
     * @throws FlowEngineException Not thrown in this implementation.
     */
    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

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

        ExecutorResponse executorResponse;
        try {
            // Obtain the realm service and user realm for the tenant.
            RealmService realmService = IdentifierAuthenticatorServiceComponent.getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);

            if (userRealm == null) {
                log.debug("Cannot find the user realm for the given tenant: " + tenantDomain);
                executorResponse = new ExecutorResponse(STATUS_ERROR);
                return executorResponse;
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            String resolvedUsername = resolveQualifiedUsername(username, userStoreManager);
            Claim[] claims = userStoreManager.getUserClaimValues(resolvedUsername, null);
            if (claims != null && claims.length > 0) {
                Map<String, String> claimMap = Arrays.stream(claims)
                        .filter(c -> c != null && c.getClaimUri() != null)
                        .collect(Collectors.toMap(Claim::getClaimUri, Claim::getValue));
                context.getFlowUser().addClaims(claimMap);
            }
            executorResponse = new ExecutorResponse(STATUS_COMPLETE);

        } catch (UserStoreException e) {
            log.debug("Error while fetching attributes for: " +
                    LoggerUtils.getMaskedContent(username) + " in tenant: " + tenantDomain, e);
            executorResponse = new ExecutorResponse(STATUS_ERROR);
        }
        return executorResponse;
    }

    /**
     * Resolves the fully qualified username by checking all user stores.
     *
     * @param username           Username to resolve.
     * @param userStoreManager   User store manager.
     * @return Fully qualified username if found, otherwise the original username.
     * @throws UserStoreException If an error occurs while accessing the user store.
     */
    private String resolveQualifiedUsername(String username, UserStoreManager userStoreManager)
            throws UserStoreException {

        // If user exists or username already contains domain, return as is.
        if (userStoreManager.isExistingUser(username) || username.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {
            return username;
        }

        // Iterate through secondary user stores to find the user.
        UserStoreManager secondaryUserStoreManager = userStoreManager.getSecondaryUserStoreManager();
        while (secondaryUserStoreManager != null) {
            String domain = secondaryUserStoreManager.getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

            if (StringUtils.isNotBlank(domain)) {
                String domainQualifiedUsername = domain + UserCoreConstants.DOMAIN_SEPARATOR + username;
                if (userStoreManager.isExistingUser(domainQualifiedUsername)) {
                    return domainQualifiedUsername;
                }
            }
            secondaryUserStoreManager = secondaryUserStoreManager.getSecondaryUserStoreManager();
        }

        // If no user found in any user store, return the original username.
        return username;
    }
}
