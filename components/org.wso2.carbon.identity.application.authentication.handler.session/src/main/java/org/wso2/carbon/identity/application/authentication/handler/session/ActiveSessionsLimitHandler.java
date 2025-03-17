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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.session.exception.UserSessionRetrievalException;
import org.wso2.carbon.identity.application.authentication.handler.session.exception.UserSessionTerminationException;
import org.wso2.carbon.identity.application.authentication.handler.session.internal.ActiveSessionsLimitHandlerServiceHolder;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.UserAgent;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.handler.session.ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT;
import static org.wso2.carbon.identity.application.authentication.handler.session.ActiveSessionsLimitHandlerConstants.SESSIONS;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.AUTHENTICATOR_MESSAGE;

/**
 * Handler for multiple active user sessions.
 */
public class ActiveSessionsLimitHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final Log log = LogFactory.getLog(ActiveSessionsLimitHandler.class);

    private static final long serialVersionUID = -1304814600410853867L;
    private static final String REDIRECT_URL = "/authenticationendpoint/handle-multiple-sessions.do";
    public static final String DEFAULT_MAX_SESSION_COUNT = "1";
    public static final String PROMPT_ID = "promptId";
    public static final String PROMPT_RESP = "promptResp";

    public static final String SP_NAME = "sp";
    public static final String PROMPT_RESP_PARAM = "promptResp.param";
    public static final String PROMPT_ID_PARAM = "promptId.param";
    public static final String ACTIVE_SESSIONS_LIMIT_ACTION_PARAM = "activeSessionsLimitAction.param";
    public static final String SESSIONS_TO_TERMINATE_PARAM = "sessionsToTerminate.param";
    public static final String DISPLAY_PROMPT_RESPONSE = "Prompt Response";
    public static final String DISPLAY_PROMPT_ID = "Prompt ID";
    public static final String DISPLAY_ACTIVE_SESSIONS_LIMIT_ACTION = "Active Sessions Limit Action";
    public static final String DISPLAY_SESSIONS_TO_TERMINATE = "Sessions to Terminate";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String activeSessionsLimitAction = request
                .getParameter(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION);
        return activeSessionsLimitAction != null;
    }

    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (!context.isLogoutRequest()) {
            String maxSessionCountParamValue =
                    getAuthenticatorParams
                            (ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT, DEFAULT_MAX_SESSION_COUNT, context);
            int maxSessionCount;
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

                StepConfig stepConfig = getCurrentSubjectIdentifierStep(context);
                AuthenticatedUser authenticatedUser = stepConfig.getAuthenticatedUser();
                context.setSubject(authenticatedUser);

                String tenantDomain = getUserTenantDomain(context);
                List<UserSession> userSessions = null;
                if (userId != null) {
                    userSessions = getUserSessions(userId, tenantDomain);
                }

                if (userSessions != null && userSessions.size() >= maxSessionCount &&
                        !isSingleSignOnAttempt(context, userSessions)) {
                    prepareEndpointParams(context, maxSessionCountParamValue, userSessions);
                    return super.process(request, response, context);
                } else {
                    this.publishAuthenticationStepAttempt(request, context, context.getSubject(), true);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
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
            Map<String, String> paramMap = new HashMap<>();
            paramMap.put(PROMPT_ID, context.getContextIdentifier());
            paramMap.put(SP_NAME, context.getServiceProviderName());
            String redirectURL = FrameworkUtils.buildURLWithQueryParams(REDIRECT_URL, paramMap);
            try {
                redirectURL = ServiceURLBuilder.create().addPath(redirectURL).build().getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new AuthenticationFailedException("Error while building tenant qualified url for context: "
                        + REDIRECT_URL, e);
            }
            response.sendRedirect(redirectURL);
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
            int maxSessionCount;
            List<UserSession> userSessions;
            try {
                String userId = getUserId(context);
                String[] sessionIdsToTerminate
                        = request.getParameterValues(ActiveSessionsLimitHandlerConstants.SESSIONS_TO_TERMINATE);
                terminateSessions(userId, sessionIdsToTerminate);
                maxSessionCount = Integer.parseInt(maxSessionCountParamValue);
                String tenantDomain = getUserTenantDomain(context);
                userSessions = getUserSessions(userId, tenantDomain);
                if (userSessions != null && userSessions.size() >= maxSessionCount &&
                        !isSingleSignOnAttempt(context, userSessions)) {
                    prepareEndpointParams(context, maxSessionCountParamValue, userSessions);
                    throw new AuthenticationFailedException("Active session count: " + userSessions.size()
                            + " exceeds the specified limit: " + maxSessionCountParamValue);
                }
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

    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context)
            throws AuthenticationFailedException {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            AuthenticatorMessage authenticatorMessage =
                    (AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE);
            authenticatorData.setMessage(authenticatorMessage);
        }

        authenticatorData.setName(getName());
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setIdp(idpName);
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        setAuthParams(authenticatorData);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(PROMPT_RESP);
        requiredParams.add(PROMPT_ID);
        requiredParams.add(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION);
        authenticatorData.setRequiredParams(requiredParams);
        authenticatorData.setAdditionalData(getAdditionalData(context));
        return Optional.of(authenticatorData);
    }

    private void setAuthParams(AuthenticatorData authenticatorData) {

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata promptResponse = new AuthenticatorParamMetadata(PROMPT_RESP, DISPLAY_PROMPT_RESPONSE,
                FrameworkConstants.AuthenticatorParamType.STRING, 1, false, PROMPT_RESP_PARAM);
        AuthenticatorParamMetadata promptId =
                new AuthenticatorParamMetadata(PROMPT_ID, DISPLAY_PROMPT_ID,
                        FrameworkConstants.AuthenticatorParamType.STRING,
                        2, false, PROMPT_ID_PARAM);
        AuthenticatorParamMetadata ActiveSessionsLimitAction =
                new AuthenticatorParamMetadata(ActiveSessionsLimitHandlerConstants.ACTIVE_SESSIONS_LIMIT_ACTION,
                        DISPLAY_ACTIVE_SESSIONS_LIMIT_ACTION, FrameworkConstants.AuthenticatorParamType.STRING, 3,
                        false,
                        ACTIVE_SESSIONS_LIMIT_ACTION_PARAM);
        AuthenticatorParamMetadata sessionsToTerminate =
                new AuthenticatorParamMetadata(ActiveSessionsLimitHandlerConstants.SESSIONS_TO_TERMINATE,
                        DISPLAY_SESSIONS_TO_TERMINATE, FrameworkConstants.AuthenticatorParamType.MULTI_VALUED, 4, false,
                        SESSIONS_TO_TERMINATE_PARAM);
        authenticatorParamMetadataList.add(promptResponse);
        authenticatorParamMetadataList.add(promptId);
        authenticatorParamMetadataList.add(ActiveSessionsLimitAction);
        authenticatorParamMetadataList.add(sessionsToTerminate);

        authenticatorData.setAuthParams(authenticatorParamMetadataList);
    }

    private AdditionalData getAdditionalData(AuthenticationContext context) throws AuthenticationFailedException {

        String userId;
        List<UserSession> userSessions;
        try {
            userId = getUserId(context);
            userSessions = getUserSessions(userId, context.getTenantDomain());
        } catch (UserSessionRetrievalException e) {
            throw new AuthenticationFailedException("Error occurred while retrieving user sessions.", e);
        }

        String maxSessionCount =
                getAuthenticatorParams(ActiveSessionsLimitHandlerConstants.MAX_SESSION_COUNT, DEFAULT_MAX_SESSION_COUNT,
                        context);

        AdditionalData additionalData = new AdditionalData();
        Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put(MAX_SESSION_COUNT, maxSessionCount);
        additionalParams.put(SESSIONS, getSessionPropertiesJSON(userSessions));
        additionalParams.put(PROMPT_ID, context.getContextIdentifier());
        additionalData.setAdditionalAuthenticationParams(additionalParams);

        return additionalData;
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

    private String getSessionPropertiesJSON(List<UserSession> userSessions) {

        JSONArray sessionDataArray = new JSONArray();
        for (UserSession userSession : userSessions) {
            JSONObject sessionData = new JSONObject();
            UserAgent userAgent = new UserAgent(userSession.getUserAgent());
            sessionData.put("sessionId", userSession.getSessionId());
            sessionData.put("lastAccessTime", userSession.getLastAccessTime());
            sessionData.put("browser", userAgent.getBrowser());
            sessionData.put("platform", userAgent.getPlatform());
            sessionData.put("device", userAgent.getDevice());
            sessionDataArray.add(sessionData);
        }
        return sessionDataArray.toJSONString();
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

    private List<UserSession> getUserSessions(String userId, String tenantDomain) throws UserSessionRetrievalException {

        List<UserSession> userSessions;

        try {
            userSessions = ActiveSessionsLimitHandlerServiceHolder.getInstance()
                    .getUserSessionManagementService().getSessionsByUserId(userId, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + userSessions.size() + " for userId: " + userId);
            }
        } catch (SessionManagementException e) {
            throw new UserSessionRetrievalException("Error occurred while retrieving sessions for userId: " + userId, e);
        }
        return userSessions;
    }

    private String getUserId(AuthenticationContext authenticationContext) throws AuthenticationFailedException {

        String userId;
        StepConfig stepConfig = getCurrentSubjectIdentifierStep(authenticationContext);

        AuthenticatedUser authenticatedUser;
        if (stepConfig != null) {
            authenticatedUser = stepConfig.getAuthenticatedUser();
        } else {
            authenticatedUser = authenticationContext.getSubject();
        }
        try {
            userId = authenticatedUser.getUserId();
        } catch (UserIdNotFoundException e) {
            throw new AuthenticationFailedException("User id is not available for user: " +
                    authenticatedUser.getUserName(), e);
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
                .filter(stepConfig -> (stepConfig.isSubjectIdentifierStep())).findFirst();
        return subjectIdentifierStep.orElse(null);
    }

    private String getUserTenantDomain(AuthenticationContext context) throws AuthenticationFailedException {

        String tenantDomain = context.getTenantDomain();
        AuthenticatedUser authenticatedUser = context.getSubject();
        if (authenticatedUser != null) {
            String userAccessingOrganization = authenticatedUser.getAccessingOrganization();
            if (StringUtils.isNotBlank(userAccessingOrganization)) {
                try {
                    tenantDomain = ActiveSessionsLimitHandlerServiceHolder.getInstance().getOrganizationManager()
                            .resolveTenantDomain(userAccessingOrganization);
                } catch (OrganizationManagementException e) {
                    throw new AuthenticationFailedException(
                            "Error occurred while resolving tenant domain of the accessing organization.", e);
                }
            }
        }
        return tenantDomain;
    }

    /**
     * Check whether the current authentication attempt is a single sign-on attempt.
     *
     * @param context      Authentication context.
     * @param userSessions List of user sessions.
     * @return True if the current authentication attempt is a single sign-on attempt.
     */
    private boolean isSingleSignOnAttempt(AuthenticationContext context, List<UserSession> userSessions) {

        String sessionIdFromContext = context.getSessionIdentifier();
        if (userSessions != null && StringUtils.isNotBlank(sessionIdFromContext)) {
            return userSessions.stream()
                    .anyMatch(userSession -> sessionIdFromContext.equals(userSession.getSessionId()));
        }
        return false;
    }
}
