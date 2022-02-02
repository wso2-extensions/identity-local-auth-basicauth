/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authentication.handler.session;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.store.UserSessionStore;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.session.exception.UserIdRetrievalException;
import org.wso2.carbon.identity.application.authentication.handler.session.exception.UserSessionRetrievalException;
import org.wso2.carbon.identity.application.authentication.handler.session.exception.UserSessionTerminationException;
import org.wso2.carbon.identity.application.authentication.handler.session.internal.ActiveSessionsLimitHandlerServiceHolder;
import org.wso2.carbon.identity.core.model.UserAgent;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Handler for multiple active user sessions.
 */
public class ActiveSessionsLimitHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final Log log = LogFactory.getLog(ActiveSessionsLimitHandler.class);

    private static final long serialVersionUID = -1304814600410853867L;
    private static final String REDIRECT_URL = "/authenticationendpoint/handle-multiple-sessions.do";
    public static final String DEFAULT_MAX_SESSION_COUNT = "1";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String activeSessionsLimitAction = request
                .getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION);
        return activeSessionsLimitAction != null;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (!context.isLogoutRequest()) {
            String maxSessionCountParamValue =
                    getAuthenticatorParams
                            (ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT, DEFAULT_MAX_SESSION_COUNT, context);
            Integer maxSessionCount;
            try {
                maxSessionCount = Integer.parseInt(maxSessionCountParamValue);
            } catch (NumberFormatException e) {
                log.error("'MaxSessionCount' must be an integer value.");
                this.publishAuthenticationStepAttempt(request, context, context.getSubject(), false);
                context.setRetrying(false);
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }

            if (maxSessionCount <= 0) {
                log.error("'MaxSessionCount' must be greater than zero. Current value is " + maxSessionCount);
                this.publishAuthenticationStepAttempt(request, context, context.getSubject(), false);
                context.setRetrying(false);
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }

            if (request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION) != null &&
                    StringUtils.equals(
                            request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION),
                            ActiveSessionsLimitHandlerConstants.DENY_LOGIN_ACTION)) {
                if (log.isDebugEnabled()) {
                    log.debug("User: " + context.getSubject() + " denied the login.");
                }
                this.publishAuthenticationStepAttempt(request, context, context.getSubject(), false);
                context.setRetrying(false);
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }

            try {

                String userId = getUserId(context);

                List<UserSession> userSessions = null;
                if (userId != null) {
                    userSessions = getUserSessions(userId);
                }

                if (userSessions != null && userSessions.size() >= maxSessionCount) {
                    prepareEndpointParams(context, maxSessionCountParamValue, userSessions);
                    return super.process(request, response, context);
                } else {
                    this.publishAuthenticationStepAttempt(request, context, context.getSubject(), true);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
            } catch (UserIdRetrievalException e) {
                throw new AuthenticationFailedException("Error occurred while retrieving the userId.", e);
            } catch (UserSessionRetrievalException e) {
                this.publishAuthenticationStepAttempt(request, context, context.getSubject(), false);
                throw new AuthenticationFailedException("Error occurred while retrieving user sessions.", e);
            }
        } else {
            return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            response.sendRedirect(REDIRECT_URL + "?promptId=" + context.getContextIdentifier());
        } catch (IOException e) {
            throw new AuthenticationFailedException("Error occurred while redirecting to: " + REDIRECT_URL
                    + "?promptId=" + context.getContextIdentifier(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION) != null &&
                StringUtils.equals(
                        request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION),
                        ActiveSessionsLimitHandlerConstants.TERMINATE_SESSIONS_ACTION)) {
            String maxSessionCountParamValue =
                    getAuthenticatorParams(ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT
                            , DEFAULT_MAX_SESSION_COUNT, context);
            Integer maxSessionCount;
            List<UserSession> userSessions;
            try {
                String userId = getUserId(context);
                String[] sessionIds = request.getParameterValues(ActiveSessionsLimitHandlerConstants.SESSIONS_TO_TERMINATE);
                terminateSessions(userId, sessionIds);
                maxSessionCount = Integer.parseInt(maxSessionCountParamValue);
                userSessions = getUserSessions(userId);
                if (userSessions != null && userSessions.size() >= maxSessionCount) {
                    prepareEndpointParams(context, maxSessionCountParamValue, userSessions);
                    throw new AuthenticationFailedException("Active session count: " + userSessions.size()
                            + " exceeds the specified limit: " + maxSessionCountParamValue);
                }
            } catch (UserIdRetrievalException e) {
                throw new AuthenticationFailedException("Error occurred while retrieving the userId.", e);
            } catch (UserSessionTerminationException e) {
                throw new AuthenticationFailedException("Error occurred while terminating user sessions.", e);
            } catch (UserSessionRetrievalException e) {
                throw new AuthenticationFailedException("Error occurred while retrieving user sessions.", e);
            } catch (NumberFormatException e) {
                throw new AuthenticationFailedException("'MaxSessionCount' must be an integer value.", e);
            }

        } else if (request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION) != null &&
                StringUtils.equals(
                        request.getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION),
                        ActiveSessionsLimitHandlerConstants.REFRESH_ACTION)) {
            throw new AuthenticationFailedException("Refresh action was called from the multiple session handler.");
        }

    }

    private String getAuthenticatorParams(String parameterName, String defaultValue,
                                          AuthenticationContext authenticationContext) {

        Map<String, String> contextParams = authenticationContext.getAuthenticatorParams(this.getName());
        AuthenticatorConfig authenticatorConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(this.getName());
        if (contextParams != null && contextParams.get(parameterName) != null) {
            return contextParams.get(parameterName);
        } else if (authenticatorConfig != null && authenticatorConfig.getParameterMap() != null
                && authenticatorConfig.getParameterMap().get(parameterName) != null) {
            return authenticatorConfig.getParameterMap().get(parameterName);
        }
        return defaultValue;
    }

    private List<String[]> getSessionProperties(List<UserSession> userSessions) {

        return userSessions.stream()
                .map(userSession -> {
                    UserAgent userAgent = new UserAgent(userSession.getUserAgent());
                    return new String[]{
                            userSession.getSessionId(),
                            userSession.getLastAccessTime(),
                            userAgent.getBrowser(),
                            userAgent.getPlatform(),
                            userAgent.getDevice()
                    };
                })
                .collect(Collectors.toList());
    }

    private List<UserSession> getUserSessions(String userId)
            throws UserSessionRetrievalException {

        List<UserSession> userSessions;

        try {
            userSessions = ActiveSessionsLimitHandlerServiceHolder.getInstance()
                    .getUserSessionManagementService().getSessionsByUserId(userId);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + userSessions.size() + " for userId: " + userId);
            }
        } catch (SessionManagementException e) {
            throw new UserSessionRetrievalException("Error occurred while retrieving sessions for userId: " + userId, e);
        }
        return userSessions;
    }

    private String getUserId(AuthenticationContext authenticationContext) throws UserIdRetrievalException {

        String userId;
        AuthenticatedUser authenticatedUser = null;
        try {
            StepConfig stepConfig = getCurrentSubjectIdentifierStep(authenticationContext);

            if (stepConfig != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
            } else {
                authenticatedUser= authenticationContext.getSubject();
            }
            userId = getUserIDforUser(authenticatedUser);
        } catch (UserSessionException e) {
            throw new UserIdRetrievalException("Error occurred while retrieving the userId for user: "
                    + authenticatedUser.getUserName(), e);
        }
        return userId;
    }

    private void prepareEndpointParams(AuthenticationContext context,
                                       String maxSessionCountParamValue, List<UserSession> userSessions) {

        Map<String, Serializable> data = new HashMap<>();
        data.put(ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT, maxSessionCountParamValue);
        data.put(ActiveSessionsLimitHandlerConstants.SESSIONS, getSessionProperties(userSessions).toArray());
        context.addEndpointParams(data);
    }

    private void terminateSessions(String userId, String[] sessionIds) throws UserSessionTerminationException {

        for (String sessionId : sessionIds) {
            try {
                ActiveSessionsLimitHandlerServiceHolder.getInstance()
                        .getUserSessionManagementService().terminateSessionBySessionId(userId, sessionId);
                if (log.isDebugEnabled()) {
                    log.debug("Terminated user session with sessionId: " + sessionId + " of userId: " + userId);
                }
            } catch (SessionManagementException e) {
                throw new UserSessionTerminationException("Error occurred terminating user session with sessionId:" + sessionId
                        + " of userId: " + userId, e);
            }
        }
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    protected boolean retryAuthenticationEnabled(AuthenticationContext context) {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(ActiveSessionsLimitHandlerConstants.SESSION_DATA_KEY);
    }

    @Override
    public String getFriendlyName() {

        return ActiveSessionsLimitHandlerConstants.HANDLER_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return ActiveSessionsLimitHandlerConstants.HANDLER_NAME;
    }

    private StepConfig getCurrentSubjectIdentifierStep(AuthenticationContext authenticationContext) {

        if (authenticationContext.getSequenceConfig() == null) {
            // Sequence config is not yet initialized.
            return null;
        }
        // Find subjectIdentifier step.
        Map<Integer, StepConfig> stepConfigs = authenticationContext.getSequenceConfig().getStepMap();
        Optional<StepConfig> subjectIdentifierStep = stepConfigs.values().stream()
                .filter(stepConfig -> (stepConfig.isCompleted() && stepConfig.isSubjectIdentifierStep())).findFirst();
        if (subjectIdentifierStep.isPresent()) {
            return subjectIdentifierStep.get();
        }
        return null;
    }

    private String getUserIDforUser(AuthenticatedUser authenticatedUser) throws UserSessionException {

        String userId = null;
        if (authenticatedUser != null) {
            if (authenticatedUser.isFederatedUser()) {
                userId = UserSessionStore.getInstance().getUserId(authenticatedUser.getUserName(),
                        IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain()),
                        authenticatedUser.getUserStoreDomain());
            } else {
                userId = FrameworkUtils.resolveUserIdFromUsername(
                        IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain()),
                        authenticatedUser.getUserStoreDomain(), authenticatedUser.getUserName());
            }
        }
        return userId;
    }

}
