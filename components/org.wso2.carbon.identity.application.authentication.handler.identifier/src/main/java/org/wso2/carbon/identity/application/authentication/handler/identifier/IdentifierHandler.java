/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authentication.handler.identifier;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authentication.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.BasicAuthErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginUtilities;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.REMAINING_ATTEMPTS;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.IDENTIFIER_CONSENT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.RESTART_FLOW;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.LogConstants.ActionIDs.INITIATE_IDENTIFIER_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.LogConstants.IDENTIFIER_AUTH_SERVICE;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.IS_USER_RESOLVED;
import static org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandlerConstants.USERNAME_USER_INPUT;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_CONFIRMATION_PENDING;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_IS_DISABLED;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_IS_LOCKED;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_LOCKED_REASON;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.INVALID_CREDENTIALS_ARE_PROVIDED;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME;

/**
 * Identifier based handler.
 */
public class IdentifierHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final long serialVersionUID = 1819664539416029785L;
    private static final Log log = LogFactory.getLog(IdentifierHandler.class);
    private static final String PROMPT_CONFIRMATION_WINDOW = "promptConfirmationWindow";
    private static final String SKIP_IDENTIFIER_PRE_PROCESS = "skipIdentifierPreProcess";
    private static final String CONTINUE = "continue";
    private static final String RESET = "reset";
    private static final String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    private static final String VALIDATE_USERNAME_ADAPTIVE_SCRIPT_PARAM = "ValidateUsername";
    public static final String USER_PROMPT = "USER_PROMPT";

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String userName = request.getParameter(IdentifierHandlerConstants.USER_NAME);
        String identifierConsent = request.getParameter(IDENTIFIER_CONSENT);
        String restart = request.getParameter(RESTART_FLOW);
        Cookie autoLoginCookie = AutoLoginUtilities.getAutoLoginCookie(request.getCookies());
        boolean canHandle = userName != null || identifierConsent != null || restart != null || autoLoginCookie != null;
        if (LoggerUtils.isDiagnosticLogsEnabled() && canHandle) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    IDENTIFIER_AUTH_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("Identifier Handler is handling the request.")
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

        Cookie autoLoginCookie = AutoLoginUtilities.getAutoLoginCookie(request.getCookies());
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (autoLoginCookie != null &&
                !Boolean.TRUE.equals(
                        context.getProperty(AutoLoginConstant.IDF_AUTO_LOGIN_FLOW_HANDLED)) &&
                AutoLoginUtilities.isEnableAutoLoginEnabled(context, autoLoginCookie)) {
            try {
                context.setProperty(AutoLoginConstant.IDF_AUTO_LOGIN_FLOW_HANDLED, true);
                return executeAutoLoginFlow(context, autoLoginCookie, response);
            } catch (AuthenticationFailedException e) {
                request.setAttribute(FrameworkConstants.REQ_ATTR_HANDLED, true);
                // Decide whether we need to redirect to the login page to retry authentication.
                boolean sendToMultiOptionPage =
                        isStepHasMultiOption(context) && isRedirectToMultiOptionPageOnFailure();
                if (retryAuthenticationEnabled(context) && !sendToMultiOptionPage) {
                    // The Authenticator will re-initiate the authentication and retry.
                    context.setCurrentAuthenticator(getName());
                    initiateAuthenticationRequest(request, response, context);
                    return AuthenticatorFlowStatus.INCOMPLETE;
                } else {
                    context.setProperty(FrameworkConstants.LAST_FAILED_AUTHENTICATOR, getName());
                    // By throwing this exception step handler will redirect to multi options page if
                    // multi-option are available in the step.
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while executing the Auto Login from Cookie flow: " + e);
                    }
                    throw e;
                }
            }
        } else {
            if (context.getPreviousAuthenticatedIdPs().get(BasicAuthenticatorConstants.LOCAL) != null) {
                AuthenticatedIdPData local = context.getPreviousAuthenticatedIdPs().get(BasicAuthenticatorConstants.LOCAL);
                if (local.getAuthenticators().size() > 0) {
                    for (AuthenticatorConfig authenticatorConfig : local.getAuthenticators()) {
                        if (authenticatorConfig.getApplicationAuthenticator() instanceof BasicAuthenticator) {
                            boolean isPrompt = Boolean.parseBoolean(context.getAuthenticatorParams(this
                                    .getName()).get(PROMPT_CONFIRMATION_WINDOW));

                            if (isPrompt) {
                                String identifierConsent = request.getParameter(IDENTIFIER_CONSENT);
                                if (CONTINUE.equals(identifierConsent)) {
                                    context.setSubject(local.getUser());
                                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                                } else if (RESET.equals(identifierConsent)) {
                                    initiateAuthenticationRequest(request, response, context);
                                    return AuthenticatorFlowStatus.INCOMPLETE;
                                } else if (request.getParameter(IdentifierHandlerConstants.USER_NAME) != null) {
                                    processAuthenticationResponse(request, response, context);
                                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                                } else {
                                    String identifierFirstConfirmationURL = ConfigurationFacade.getInstance().getIdentifierFirstConfirmationURL();
                                    String queryParams = context.getContextIdIncludedQueryParams();
                                    try {
                                        queryParams = queryParams + "&username=" + local.getUser()
                                                .toFullQualifiedUsername();
                                        response.sendRedirect(identifierFirstConfirmationURL + ("?" + queryParams));
                                        return AuthenticatorFlowStatus.INCOMPLETE;
                                    } catch (IOException e) {
                                        throw new AuthenticationFailedException(
                                                ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                                                e.getMessage(), e);
                                    }
                                }
                            } else {
                                context.setSubject(local.getUser());
                                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                            }
                        }
                    }
                }
            } else if (request.getParameter(IDENTIFIER_CONSENT) != null) {
                //submit from the confirmation page.
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else if (request.getParameter(RESTART_FLOW) != null) {
                // Restart the flow from identifier first.
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    IDENTIFIER_AUTH_SERVICE, INITIATE_IDENTIFIER_AUTH_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating identifier first authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        if (parameterMap != null) {
            showAuthFailureReason = parameterMap.get("showAuthFailureReason");
            if (log.isDebugEnabled()) {
                log.debug("showAuthFailureReason has been set as : " + showAuthFailureReason);
            }
        }

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String retryPage = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        String queryParams = context.getContextIdIncludedQueryParams();

        try {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        IDENTIFIER_AUTH_SERVICE, INITIATE_IDENTIFIER_AUTH_REQUEST);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context));
            }
            String retryParam = "";

            if (context.isRetrying()) {
                if (context.getProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME) != null &&
                        (Boolean) context.getProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME)) {
                    retryParam = "&authFailure=true&authFailureMsg=emailusername.fail.message";
                    context.setProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME, false);
                } else {
                    retryParam = "&authFailure=true&authFailureMsg=username.fail.message";
                }
            }

            if (context.getProperty("UserTenantDomainMismatch") != null &&
                    (Boolean) context.getProperty("UserTenantDomainMismatch")) {
                retryParam = "&authFailure=true&authFailureMsg=user.tenant.domain.mismatch.message";
                context.setProperty("UserTenantDomainMismatch", false);
            }

            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();

            if (errorContext != null && errorContext.getErrorCode() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is not null");
                }
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.FAILED);
                }
                String errorCode = errorContext.getErrorCode();

                if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE)) {
                    retryParam = "&authFailure=true&authFailureMsg=account.confirmation.pending";
                    String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                    }

                    String redirectURL = loginPage + ("?" + queryParams) + IdentifierHandlerConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, IdentifierHandlerConstants.UTF_8) +
                            IdentifierHandlerConstants.ERROR_CODE + errorCode + IdentifierHandlerConstants
                            .AUTHENTICATORS + getName() + ":" + IdentifierHandlerConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.FAILED)
                                .resultMessage("Account confirmation pending for user.")
                                .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                        LoggerUtils.getMaskedContent(username) : username);
                    }

                    setAuthenticatorMessage(getErrorMessage(errorCode, ACCOUNT_CONFIRMATION_PENDING), context);
                } else if ("true".equals(showAuthFailureReason)) {

                    String reason = null;
                    if (errorCode.contains(":")) {
                        String[] errorCodeReason = errorCode.split(":");
                        errorCode = errorCodeReason[0];
                        if (errorCodeReason.length > 1) {
                            reason = errorCodeReason[1];
                        }
                    }
                    int remainingAttempts =
                            errorContext.getMaximumLoginAttempts() - errorContext.getFailedLoginAttempts();

                    if (log.isDebugEnabled()) {
                        log.debug("errorCode : " + errorCode);
                        log.debug("username : " + request.getParameter(IdentifierHandlerConstants.USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8)
                                + "&remainingAttempts=" + remainingAttempts;
                        String redirectURL = loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                            diagnosticLogBuilder.resultMessage("Invalid credentials.")
                                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(username) : username)
                                    .inputParam("remaining attempts", remainingAttempts);
                        }
                        Map<String, String> messageContext = getMessageContext(REMAINING_ATTEMPTS,
                                String.valueOf(remainingAttempts));
                        setAuthenticatorMessage(new AuthenticatorMessage
                                (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                                        INVALID_CREDENTIALS_ARE_PROVIDED, messageContext), context);
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        String redirectURL = retryPage;
                        if (remainingAttempts == 0) {
                            if (StringUtils.isBlank(reason)) {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        IdentifierHandlerConstants.ERROR_CODE + errorCode + IdentifierHandlerConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(IdentifierHandlerConstants.USER_NAME), IdentifierHandlerConstants.UTF_8) +
                                        "&remainingAttempts=0";
                            } else {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        IdentifierHandlerConstants.ERROR_CODE + errorCode + "&lockedReason="
                                        + reason + IdentifierHandlerConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                                IdentifierHandlerConstants.UTF_8) + "&remainingAttempts=0";
                            }
                        } else {
                            if (StringUtils.isBlank(reason)) {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        IdentifierHandlerConstants.ERROR_CODE + errorCode + IdentifierHandlerConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(IdentifierHandlerConstants.USER_NAME), IdentifierHandlerConstants.UTF_8);
                            } else {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        IdentifierHandlerConstants.ERROR_CODE + errorCode + "&lockedReason="
                                        + reason + IdentifierHandlerConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                                IdentifierHandlerConstants.UTF_8);
                            }
                            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                                diagnosticLogBuilder.inputParam("locked reason", reason);
                            }
                        }
                        response.sendRedirect(redirectURL);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                            diagnosticLogBuilder.resultMessage("User is locked.")
                                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(username) : username);
                        }

                        Map<String, String> messageContext = getMessageContext(ACCOUNT_LOCKED_REASON,
                                String.valueOf(reason));
                        setAuthenticatorMessage(new AuthenticatorMessage
                                        (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                                                ACCOUNT_IS_LOCKED, messageContext), context);
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        String redirectURL = loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                            diagnosticLogBuilder.resultMessage("User does not exist.")
                                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(username) : username);
                        }
                        setAuthenticatorMessage(getErrorMessage(errorCode,
                                INVALID_CREDENTIALS_ARE_PROVIDED), context);
                    } else if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        String redirectURL = loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                            diagnosticLogBuilder.resultMessage("User account is disabled.")
                                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(username) : username);
                        }
                        setAuthenticatorMessage(getErrorMessage(errorCode, ACCOUNT_IS_DISABLED), context);
                    } else {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        String redirectURL = loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":"
                                + IdentifierHandlerConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                        if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                            String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);
                            diagnosticLogBuilder.resultMessage("Unknown error occurred.")
                                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                            LoggerUtils.getMaskedContent(username) : username);
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                    String redirectURL = loginPage + ("?" + queryParams)
                            + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                            IdentifierHandlerConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);
                    if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                        diagnosticLogBuilder.resultMessage("Unknown identity error code.");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                String redirectURL = loginPage + ("?" + queryParams) + IdentifierHandlerConstants.AUTHENTICATORS +
                        getName() + ":" + IdentifierHandlerConstants.LOCAL + retryParam;
                response.sendRedirect(redirectURL);
                if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                    diagnosticLogBuilder.resultMessage("Redirecting to login page.");
                }
            }
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                    e.getMessage(),
                    User.getUserFromUserName(request.getParameter(IdentifierHandlerConstants.USER_NAME)), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        DiagnosticLog.DiagnosticLogBuilder authProcessCompletedDiagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing identifier first authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);

            authProcessCompletedDiagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    IDENTIFIER_AUTH_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            authProcessCompletedDiagnosticLogBuilder.inputParams(getApplicationDetails(context))
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep());
        }
        Map<String, String> runtimeParams = getRuntimeParams(context);
        String identifierFromRequest = request.getParameter(IdentifierHandlerConstants.USER_NAME);
        String validateUsernameAdaptiveParam = null;
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw new InvalidCredentialsException(ErrorMessages.EMPTY_USERNAME.getCode(),
                    ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        context.setProperty(USERNAME_USER_INPUT, identifierFromRequest);
        if (runtimeParams != null) {
            String skipPreProcessUsername = runtimeParams.get(SKIP_IDENTIFIER_PRE_PROCESS);
            validateUsernameAdaptiveParam = runtimeParams.get(VALIDATE_USERNAME_ADAPTIVE_SCRIPT_PARAM);
            if (Boolean.parseBoolean(skipPreProcessUsername)) {
                persistUsername(context, identifierFromRequest);

                // Since the pre-processing is skipped, user id is not populated.
                AuthenticatedUser user = new AuthenticatedUser();
                user.setUserName(identifierFromRequest);
                context.setSubject(user);
                if (LoggerUtils.isDiagnosticLogsEnabled() && authProcessCompletedDiagnosticLogBuilder != null) {
                    authProcessCompletedDiagnosticLogBuilder.resultMessage("Identifier first authentication " +
                                    "successful.")
                            .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                    LoggerUtils.getMaskedContent(identifierFromRequest) : identifierFromRequest);
                    LoggerUtils.triggerDiagnosticLogEvent(authProcessCompletedDiagnosticLogBuilder);
                }
                return;
            }
        }

        String username = identifierFromRequest;
        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
            FrameworkUtils.validateUsername(identifierFromRequest, context);
            username = FrameworkUtils.preprocessUsername(identifierFromRequest, context);
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userId = null;
        String userStoreDomain = null;

        /*
         This is going to be removed after the multi attribute user resolving logic is moved to each authenticator.
         Hence, don't rely on this logic for new authenticators.
         */
        if (IdentifierAuthenticatorServiceComponent.getMultiAttributeLogin().isEnabled(context.getTenantDomain())) {
            ResolvedUserResult resolvedUserResult = IdentifierAuthenticatorServiceComponent.getMultiAttributeLogin().
                    resolveUser(tenantAwareUsername, tenantDomain);
            if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.
                    equals(resolvedUserResult.getResolvedStatus())) {
                tenantAwareUsername = resolvedUserResult.getUser().getUsername();
                username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, tenantDomain);
                userId = resolvedUserResult.getUser().getUserID();
                userStoreDomain = resolvedUserResult.getUser().getUserStoreDomain();
                // Set a property to the context to indicate that the user is resolved from this step.
                setIsUserResolvedToContext(context);
            }
        }

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        /*
          If the "ValidateUsername" adaptive parameter is null, the "ValidateUsername" authenticator config
          should be considered. Therefore, we need to have the null check to have that distinction.
          If the "ValidateUsername" adaptive parameter is set, it should be honoured regardless of the
          authenticator config.
         */
        if (StringUtils.isNotBlank(validateUsernameAdaptiveParam)) {
            if (Boolean.parseBoolean(validateUsernameAdaptiveParam)) {
                boolean isUsernameValidationRequired = false;
                if (context.getCallerPath() != null && context.getCallerPath().startsWith("/t/")) {
                    String requestTenantDomain = context.getUserTenantDomain();
                    if (StringUtils.isNotBlank(requestTenantDomain) &&
                            !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(requestTenantDomain)) {
                        try {
                            int tenantId = IdentityTenantUtil.getTenantId(requestTenantDomain);
                            Tenant tenant = (Tenant) IdentifierAuthenticatorServiceComponent.getRealmService()
                                    .getTenantManager().getTenant(tenantId);
                            if (tenant != null && StringUtils.isNotBlank(tenant.getAssociatedOrganizationUUID())) {
                                isUsernameValidationRequired = true;
                                org.wso2.carbon.user.core.common.User user = IdentifierAuthenticatorServiceComponent
                                        .getOrganizationUserResidentResolverService()
                                        .resolveUserFromResidentOrganization(tenantAwareUsername, null,
                                                tenant.getAssociatedOrganizationUUID())
                                        .orElseThrow(() -> new AuthenticationFailedException(
                                                ErrorMessages.USER_NOT_IDENTIFIED_IN_HIERARCHY.getCode()));
                                tenantAwareUsername = user.getUsername();
                                username = UserCoreUtil.addTenantDomainToEntry(
                                        tenantAwareUsername, user.getTenantDomain());
                                userId = user.getUserID();
                                userStoreDomain = user.getUserStoreDomain();
                            }
                        } catch (OrganizationManagementException e) {
                            if (log.isDebugEnabled()) {
                                log.debug("IdentifierHandler failed while trying to resolving user's " +
                                        "resident org.", e);
                            }
                            throw new AuthenticationFailedException(
                                    ErrorMessages.ORGANIZATION_MGT_EXCEPTION_WHILE_TRYING_TO_RESOLVE_RESIDENT_ORG
                                            .getCode(), e.getMessage(), User.getUserFromUserName(username), e);
                        } catch (UserStoreException e) {
                            if (log.isDebugEnabled()) {
                                log.debug("IdentifierHandler failed while trying to authenticate.", e);
                            }
                            throw new AuthenticationFailedException(
                                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(),
                                    e.getMessage(), User.getUserFromUserName(username), e);
                        }
                    }
                }

                // If the user is not validated against resident orgs, then try to validate in the normal path.
                if (!isUsernameValidationRequired) {
                    String[] userDetails = validateUsername(tenantDomain, username, tenantAwareUsername,
                            identifierFromRequest, userId);
                    userId = userDetails[0];
                    if (StringUtils.isNotEmpty(userDetails[1])) {
                        userStoreDomain = userDetails[1];
                    }
                }

                // TODO: user tenant domain has to be an attribute in the AuthenticationContext.
                authProperties.put("user-tenant-domain", tenantDomain);
            }
        } else if (getAuthenticatorConfig().getParameterMap() != null &&
                Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().get("ValidateUsername"))) {
            // If the "ValidateUsername" adaptive parameter is not set, then check for the authenticator config.

            String[] userDetails = validateUsername(tenantDomain, username, tenantAwareUsername,
                    identifierFromRequest, userId);
            userId = userDetails[0];
            if (StringUtils.isNotEmpty(userDetails[1])) {
                userStoreDomain = userDetails[1];
            }

            // TODO: user tenant domain has to be an attribute in the AuthenticationContext.
            authProperties.put("user-tenant-domain", tenantDomain);
        }

        username = FrameworkUtils.prependUserStoreDomainToName(username);
        authProperties.put("username", username);

        persistUsername(context, username);

        if (userStoreDomain == null) {
            userStoreDomain = IdentityUtil.extractDomainFromName(username);
        }

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(userId);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);
        context.setSubject(user);
        if (LoggerUtils.isDiagnosticLogsEnabled() && authProcessCompletedDiagnosticLogBuilder != null) {
            authProcessCompletedDiagnosticLogBuilder.resultMessage("Identifier first authentication successful.")
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(username) : username)
                    .inputParam("user store domain", userStoreDomain)
                    .inputParam(LogConstants.InputKeys.USER_ID, userId);
            LoggerUtils.triggerDiagnosticLogEvent(authProcessCompletedDiagnosticLogBuilder);
        }
    }

    private static void setAuthenticatorMessage(AuthenticatorMessage errorMessage, AuthenticationContext context) {

        context.setProperty(AUTHENTICATOR_MESSAGE, errorMessage);
    }

    private static AuthenticatorMessage getErrorMessage(String errorCode, String accountConfirmationPending) {

        return new AuthenticatorMessage
                (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                        accountConfirmationPending, null);
    }

    private static Map<String, String> getMessageContext(String key, String value) {

        Map <String,String> messageContext = new HashMap<>();
        messageContext.put(key, value);
        return messageContext;
    }

    private void setIsUserResolvedToContext(AuthenticationContext context) {

        Map<String, Object> properties = context.getProperties();
        if (properties == null) {
            properties = new HashMap<>();
        }
        properties.put(IS_USER_RESOLVED, true);
        context.setProperties(properties);
    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    protected AuthenticatorFlowStatus executeAutoLoginFlow(AuthenticationContext context, Cookie autoLoginCookie,
                                                           HttpServletResponse response)
            throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(autoLoginCookie.getValue()));
        JSONObject cookieValueJSON = AutoLoginUtilities.transformToJSON(decodedValue);
        String signature = (String) cookieValueJSON.get(AutoLoginConstant.SIGNATURE);
        String content = (String) cookieValueJSON.get(AutoLoginConstant.CONTENT);
        JSONObject contentJSON = AutoLoginUtilities.transformToJSON(content);
        try {
            AutoLoginUtilities.validateAutoLoginCookie(context, getAuthenticatorConfig(), content, signature);
        } catch (AuthenticationFailedException e) {
            // Remove Auto login cookie in the response, if cookie validation failed.
            AutoLoginUtilities.removeAutoLoginCookieInResponse(response, autoLoginCookie);
            throw e;
        }

        String usernameInCookie = (String) contentJSON.get(AutoLoginConstant.USERNAME);

        if (log.isDebugEnabled()) {
            log.debug("Started executing Auto Login from Cookie flow.");
        }

        String userStoreDomain = UserCoreUtil.extractDomainFromName(usernameInCookie);
        // Set the user store domain in thread local as downstream code depends on it. This will be cleared at the
        // end of the request at the framework.
        UserCoreUtil.setDomainInThreadLocal(userStoreDomain);

        usernameInCookie = FrameworkUtils.prependUserStoreDomainToName(usernameInCookie);

        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(usernameInCookie));
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {
        return IdentifierHandlerConstants.HANDLER_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return IdentifierHandlerConstants.HANDLER_NAME;
    }

    private void persistUsername(AuthenticationContext context, String username) {

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams = new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        //Identifier first is the first authenticator.
        context.getPreviousAuthenticatedIdPs().clear();
        context.addAuthenticatorParams(contextParams);
    }

    /**
     * Validate the username against the user store.
     * If not found in the PRIMARY userstore and the username is not domain qualified,
     * then search in secondary userstores.
     *
     * @param tenantDomain          Tenant domain.
     * @param username              Username of the user.
     * @param tenantAwareUsername   Tenant aware username.
     * @param identifierFromRequest Identifier provided in the request.
     * @param userId                User id if present.
     * @return User id and user store domain (If found from secondary user stores).
     * @throws AuthenticationFailedException If user not found or an error happens.
     */
    private String[] validateUsername(String tenantDomain, String username, String tenantAwareUsername,
                                      String identifierFromRequest, String userId)
            throws AuthenticationFailedException {

        AbstractUserStoreManager userStoreManager;
        String userStoreDomain = null;
        // Check for the username exists.
        try {
            int tenantId = IdentifierAuthenticatorServiceComponent
                    .getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = IdentifierAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);

            if (userRealm == null) {
                throw new AuthenticationFailedException(
                        ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getCode(), String.format(
                        ErrorMessages.CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT.getMessage(), tenantId),
                        User.getUserFromUserName(username));
            }

            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();

            // If the user id is already resolved from the multi attribute login, we can assume the user
            // exists. If not, we will try to resolve the user id, which will indicate if the user exists
            // or not.
            if (userId == null) {
                userId = userStoreManager.getUserIDFromUserName(tenantAwareUsername);
            }

            // If the userId is still not resolved and the username is not domain qualified, try to find
            // the user from secondary user stores.
            if (userId == null && StringUtils.equals(identifierFromRequest, tenantAwareUsername)) {
                UserStoreManager secondaryUserStoreManager = userStoreManager.getSecondaryUserStoreManager();
                while (secondaryUserStoreManager != null) {
                    String domain = secondaryUserStoreManager.getRealmConfiguration()
                            .getUserStoreProperties().get(PROPERTY_DOMAIN_NAME);
                    if (userStoreManager.isExistingUser(domain + DOMAIN_SEPARATOR +
                            tenantAwareUsername)) {
                        userId = userStoreManager.getUserIDFromUserName(
                                domain + DOMAIN_SEPARATOR + tenantAwareUsername);
                        userStoreDomain = domain;
                        break;
                    }
                    secondaryUserStoreManager = secondaryUserStoreManager.getSecondaryUserStoreManager();
                }
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("IdentifierHandler failed while trying to get the tenant ID of the user " +
                        username, e);
            }
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TENANT_ID_OF_THE_USER.getCode(),
                    e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("IdentifierHandler failed while trying to authenticate.", e);
            }
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                    User.getUserFromUserName(username), e);
        }

        if (userId == null) {
            if (log.isDebugEnabled()) {
                log.debug("User does not exists.");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                username = IdentityUtil.addDomainToName(
                        username, IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN)
                                .toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
            throw new InvalidCredentialsException(ErrorMessages.USER_DOES_NOT_EXISTS.getCode(),
                    ErrorMessages.USER_DOES_NOT_EXISTS.getMessage(), User.getUserFromUserName(username));
        }

        return new String[]{userId, userStoreDomain};
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
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setIdp(idpName);
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(BasicAuthenticatorConstants.USER_NAME);
        authenticatorData.setRequiredParams(requiredParams);

        setAuthParams(authenticatorData);

        return Optional.of(authenticatorData);
    }

    private static void setAuthParams(AuthenticatorData authenticatorData) {

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                BasicAuthenticatorConstants.USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, BasicAuthenticatorConstants.USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
    }
}
