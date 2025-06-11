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

import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authentication.handler.identifier.util.IdentifierErrorConstants;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * This class is responsible for resolving user attributes.
 */
public class UserResolveExecutor implements Executor {

    public static final String USER_RESOLVE_EXECUTOR = "UserResolveExecutor";
    public static final String CLAIM_URI_USERNAME = "http://wso2.org/claims/username";
    public static final String CLAIM_URI_EMAIL = "http://wso2.org/claims/emailaddress";
    public static final String CLAIM_URI_MOBILE = "http://wso2.org/claims/mobile";
    public static final String CLAIM_URI_FIRST_NAME = "http://wso2.org/claims/givenname";
    public static final String CLAIM_URI_LAST_NAME = "http://wso2.org/claims/lastname";
    private static final Log log = LogFactory.getLog(UserResolveExecutor.class);

    public String getName() {

        return USER_RESOLVE_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) throws FlowEngineException {

        ExecutorResponse response;
        String usernameClaimValue = (String) context.getFlowUser().getClaim(CLAIM_URI_USERNAME);
        if (usernameClaimValue != null) {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(usernameClaimValue);
            resolveUser(tenantAwareUsername, context.getTenantDomain(), context);
            response = new ExecutorResponse(STATUS_COMPLETE);
        } else {
            response = new ExecutorResponse(STATUS_USER_INPUT_REQUIRED);
        }
        return response;
    }

    private void resolveUser(String username, String tenantDomain, FlowExecutionContext context) {

        try {
            RealmService realmService = IdentifierAuthenticatorServiceComponent.getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);

            if (userRealm == null) {
                throw new AuthenticationFailedException(
                        IdentifierErrorConstants.ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT
                                .getCode(), String.format(
                        IdentifierErrorConstants.ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT
                                .getMessage(), tenantId),
                        User.getUserFromUserName(username));
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            String[] claimsToFetch = {CLAIM_URI_FIRST_NAME, CLAIM_URI_LAST_NAME, CLAIM_URI_EMAIL, CLAIM_URI_MOBILE};
            Map<String, String> retrievedClaims = null;
            String resolvedUsername = username;

            if (userStoreManager.isExistingUser(username)) {
                retrievedClaims = userStoreManager.getUserClaimValues(username, claimsToFetch, null);
            }

            if ((retrievedClaims == null || retrievedClaims.isEmpty()) &&
                    !username.contains(UserCoreConstants.DOMAIN_SEPARATOR)) {

                UserStoreManager currentUSM = userRealm.getUserStoreManager();
                String primaryDomain = currentUSM.getRealmConfiguration()
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

                while (currentUSM != null) {
                    String domain = currentUSM.getRealmConfiguration()
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

                    if (StringUtils.isNotBlank(domain) && !domain.equalsIgnoreCase(primaryDomain)) {
                        String qualifiedUsername = domain + UserCoreConstants.DOMAIN_SEPARATOR + username;
                        if (userStoreManager.isExistingUser(qualifiedUsername)) {
                            resolvedUsername = qualifiedUsername;
                            retrievedClaims = userStoreManager
                                    .getUserClaimValues(resolvedUsername, claimsToFetch, null);
                            break;
                        }
                    }
                    currentUSM = currentUSM.getSecondaryUserStoreManager();
                }
            }

            if (retrievedClaims != null && !retrievedClaims.isEmpty()) {
                context.getFlowUser().addClaim(CLAIM_URI_EMAIL, retrievedClaims.get(CLAIM_URI_EMAIL));
                context.getFlowUser().addClaim(CLAIM_URI_FIRST_NAME, retrievedClaims.get(CLAIM_URI_FIRST_NAME));
                context.getFlowUser().addClaim(CLAIM_URI_LAST_NAME, retrievedClaims.get(CLAIM_URI_LAST_NAME));
                context.getFlowUser().addClaim(CLAIM_URI_MOBILE, retrievedClaims.get(CLAIM_URI_MOBILE));
            }

        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while fetching attributes for : " +
                        LoggerUtils.getMaskedContent(username) + " in tenant: " + tenantDomain, e);
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Unexpected exception while fetching attributes for : " +
                        LoggerUtils.getMaskedContent(username) + " in tenant: " + tenantDomain, e);
            }
        }
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(USERNAME_CLAIM_URI);
        return initiationData;
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
    }
}
