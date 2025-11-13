/*
 * Copyright (c) 2014-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.basicauth;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationFrameworkWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginUtilities;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.BasicAuthErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.branding.preference.management.core.exception.BrandingPreferenceMgtException;
import org.wso2.carbon.identity.branding.preference.management.core.util.BrandingPreferenceMgtUtils;
import org.wso2.carbon.identity.captcha.connector.recaptcha.SSOLoginReCaptchaConfig;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.mgt.Constants;
import org.wso2.carbon.identity.flow.mgt.exception.FlowMgtServerException;
import org.wso2.carbon.identity.flow.mgt.utils.FlowMgtConfigUtils;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.recovery.RecoveryScenarios;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.constants.UserCoreClaimConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.REMAINING_ATTEMPTS;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_CONFIRMATION_PENDING;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_IS_LOCKED;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_LOCKED_REASON;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ACCOUNT_PENDING_APPROVAL;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.ASK_PASSWORD_VIA_OTP;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.AUTHENTICATOR_BASIC;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.AUTHENTICATOR_MESSAGE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.DISPLAY_PASSWORD;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.DISPLAY_USER_NAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.FORCED_PASSWORD_RESET_VIA_EMAIL;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.FORCED_PASSWORD_RESET_VIA_OTP;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.INVALID_CREDENTIALS_ARE_PROVIDED;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.IS_INVALID_USERNAME;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.OTP_MISMATCH_IN_ADMIN_FORCED_PASSWORD_RESET;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.PASSWORD;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.RESOURCE_NAME_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.RESOURCE_TYPE_NAME_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.SHOW_PENDING_USER_INFORMATION_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.SHOW_PENDING_USER_INFORMATION_DEFAULT_VALUE;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.USERNAME_USER_INPUT;
import static org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants.USER_NAME;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_FEATURE_NOT_ENABLED;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS;

/**
 * Username Password based Authenticator.
 */
public class BasicAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 1819664539416029785L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String CONFIRM_RECOVERY_DO = "/confirmrecovery.do?";
    private static final Log log = LogFactory.getLog(BasicAuthenticator.class);
    private static final String RESEND_CONFIRMATION_RECAPTCHA_ENABLE = "SelfRegistration.ResendConfirmationReCaptcha";
    private static final String APPEND_USER_TENANT_TO_USERNAME = "appendUserTenantToUsername";
    private static final String APPEND_APP_TENANT_TO_USERNAME = "appendAppTenantToUsername";
    private static final String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    public static final String ADDITIONAL_QUERY_PARAMS = "additionalParams";
    public static final String RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS = "RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS";

    /**
     * USER_EXIST_THREAD_LOCAL_PROPERTY is used to maintain the state of user existence
     * which has used in org.wso2.carbon.identity.governance.listener.IdentityMgtEventListener.
     */
    private static final String USER_EXIST_THREAD_LOCAL_PROPERTY = "userExistThreadLocalProperty";


    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(USER_NAME);
        String password = request.getParameter(PASSWORD);
        Cookie autoLoginCookie = AutoLoginUtilities.getAutoLoginCookie(request.getCookies());
        boolean canHandle = (userName != null && password != null) || autoLoginCookie != null;
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BasicAuthenticatorConstants.LogConstants.BASIC_AUTH_SERVICE,
                    BasicAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Basic Authenticator handling the request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam("auto login cookie available", autoLoginCookie != null)
                    .inputParam("user credentials available", (userName != null && password != null));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (isURLContainSensitiveData(request, response, context)) {
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        Cookie autoLoginCookie = AutoLoginUtilities.getAutoLoginCookie(request.getCookies());
        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (autoLoginCookie != null && !Boolean.TRUE.equals(
                context.getProperty(AutoLoginConstant.BASIC_AUTH_AUTO_LOGIN_FLOW_HANDLED)) &&
                AutoLoginUtilities.isEnableAutoLoginEnabled(context, autoLoginCookie)) {
            try {
                context.setProperty(AutoLoginConstant.BASIC_AUTH_AUTO_LOGIN_FLOW_HANDLED, true);
                return executeAutoLoginFlow(request, response, context, autoLoginCookie);
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
            } finally {
                AutoLoginUtilities.removeAutoLoginCookieInResponse(response, autoLoginCookie);
            }
        } else if (runtimeParams.containsKey(USER_NAME) && runtimeParams.containsKey(PASSWORD)) {
            /*
             * If the username and password are available in the runtime params, resolve the credentials
             * from the runtime params. In this case, `skipPrompt` will be set to `true` in order to bypass
             * the execution of initiateAuthenticationRequest and send to processAuthenticationRequest method as
             * credentials are already available as runtime params.
             * Also, `RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS` property will be added as a context property to
             * indicate that the credentials are resolved from runtime params.
             */
            if (context.getCurrentStep() > 0) {
                context.setProperty(RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS, true);
                context.getSequenceConfig().getStepMap().get(context.getCurrentStep()).setSkipPrompt(true);
            }
        }
        return super.process(request, response, context);
    }

    protected AuthenticatorFlowStatus executeAutoLoginFlow(HttpServletRequest request, HttpServletResponse response,
                                                           AuthenticationContext context, Cookie autoLoginCookie)
            throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(autoLoginCookie.getValue()));
        JSONObject cookieValueJSON = AutoLoginUtilities.transformToJSON(decodedValue);
        String signature = (String) cookieValueJSON.get(AutoLoginConstant.SIGNATURE);
        String content = (String) cookieValueJSON.get(AutoLoginConstant.CONTENT);
        JSONObject contentJSON = AutoLoginUtilities.transformToJSON(content);

        AutoLoginUtilities.validateAutoLoginCookie(context, getAuthenticatorConfig(), content, signature);

        if (log.isDebugEnabled()) {
            log.debug("Started executing Auto Login from Cookie flow.");
        }
        String usernameInCookie = (String) contentJSON.get(AutoLoginConstant.USERNAME);

        String userStoreDomain = UserCoreUtil.extractDomainFromName(usernameInCookie);
        // Set the user store domain in thread local as downstream code depends on it. This will be cleared at the
        // end of the request at the framework.
        UserCoreUtil.setDomainInThreadLocal(userStoreDomain);

        usernameInCookie = FrameworkUtils.prependUserStoreDomainToName(usernameInCookie);

        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(usernameInCookie));
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BasicAuthenticatorConstants.LogConstants.BASIC_AUTH_SERVICE,
                    BasicAuthenticatorConstants.LogConstants.ActionIDs.VALIDATE_BASIC_AUTH_REQUEST);
            diagnosticLogBuilder.resultMessage("Validate authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep());
            getApplicationDetails(context, diagnosticLogBuilder);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        String showAuthFailureReasonOnLoginPage = null;
        String maskUserNotExistsErrorCode = null;
        String maskAdminForcedPasswordResetErrorCode = null;
        List<String> omittingErrorParams = null;
        if (parameterMap != null) {
            showAuthFailureReason = parameterMap.get(BasicAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON);
            if (log.isDebugEnabled()) {
                log.debug(BasicAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON + " has been set as : " +
                        showAuthFailureReason);
            }
            if (Boolean.parseBoolean(showAuthFailureReason)) {
                maskUserNotExistsErrorCode =
                        parameterMap.get(BasicAuthenticatorConstants.CONF_MASK_USER_NOT_EXISTS_ERROR_CODE);
                if (log.isDebugEnabled()) {
                    log.debug(BasicAuthenticatorConstants.CONF_MASK_USER_NOT_EXISTS_ERROR_CODE +
                            " has been set as : " + maskUserNotExistsErrorCode);
                }
                showAuthFailureReasonOnLoginPage =
                        parameterMap.get(BasicAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE);
                if (log.isDebugEnabled()) {
                    log.debug(BasicAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE +
                            " has been set as : " + showAuthFailureReasonOnLoginPage);
                }
                String errorParamsToOmit = parameterMap.get(BasicAuthenticatorConstants.CONF_ERROR_PARAMS_TO_OMIT);
                if (log.isDebugEnabled()) {
                    log.debug(BasicAuthenticatorConstants.CONF_ERROR_PARAMS_TO_OMIT + " has been set as : " +
                            errorParamsToOmit);
                }
                if (StringUtils.isNotBlank(errorParamsToOmit)) {
                    errorParamsToOmit = errorParamsToOmit.replaceAll(" ", "");
                    omittingErrorParams = new ArrayList<>(Arrays.asList(errorParamsToOmit.split(",")));
                }
            }
            maskAdminForcedPasswordResetErrorCode =
                    parameterMap.get(BasicAuthenticatorConstants.CONF_MASK_ADMIN_FORCED_PASSWORD_RESET_ERROR_CODE);
            if (log.isDebugEnabled()) {
                log.debug(BasicAuthenticatorConstants.CONF_MASK_ADMIN_FORCED_PASSWORD_RESET_ERROR_CODE +
                        " has been set as : " + maskAdminForcedPasswordResetErrorCode);
            }
        }

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String recoveryPage = ConfigurationFacade.getInstance().getAccountRecoveryEndpointPath();
        String retryPage = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        String queryParams = context.getContextIdIncludedQueryParams();
        String password = (String) context.getProperty(PASSWORD_PROPERTY);
        String redirectURL;
        String inputType = null;
        context.getProperties().remove(PASSWORD_PROPERTY);

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (runtimeParams != null) {
            String usernameFromContext = runtimeParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
            if (usernameFromContext != null) {
                inputType = FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST;
            }
            if (FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST.equalsIgnoreCase(inputType)) {
                queryParams += "&" + FrameworkConstants.RequestParams.INPUT_TYPE + "=" + inputType;
                context.addEndpointParam(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, usernameFromContext);
                context.addEndpointParam(FrameworkConstants.JSAttributes.JS_IDENTIFIER_FIRST_USER_INPUT,
                        request.getParameter(USER_NAME));
            }
            String additionalParams = runtimeParams.get(ADDITIONAL_QUERY_PARAMS);
            if (StringUtils.isNotBlank(additionalParams)) {
                queryParams += "&" + additionalParams;
            }
        }

        String loginHint = request.getParameter(BasicAuthenticatorConstants.LOGIN_HINT);

        if (StringUtils.isNotBlank(loginHint) && StringUtils.isBlank(inputType)) {
            inputType = FrameworkConstants.INPUT_TYPE_LOGIN_HINT;
            queryParams += "&" + FrameworkConstants.RequestParams.INPUT_TYPE + "=" + inputType;
            context.addEndpointParam(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, loginHint);
            String additionalParams = runtimeParams.get(ADDITIONAL_QUERY_PARAMS);
            if (StringUtils.isNotBlank(additionalParams)) {
                queryParams += "&" + additionalParams;
            }
        }

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                if (context.getProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME) != null &&
                        (Boolean) context.getProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "emailusername.fail.message";
                    context.setProperty(FrameworkConstants.CONTEXT_PROP_INVALID_EMAIL_USERNAME, false);
                } else {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "login.fail.message";
                }
            }

            if (context.getProperty("UserTenantDomainMismatch") != null &&
                    (Boolean) context.getProperty("UserTenantDomainMismatch")) {
                retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                        BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "user.tenant.domain.mismatch.message";
                context.setProperty("UserTenantDomainMismatch", false);
            }

            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            IdentityUtil.clearIdentityErrorMsg();

            if (errorContext != null && errorContext.getErrorCode() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is not null");
                }
                String errorCode = errorContext.getErrorCode();

                if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "account.confirmation.pending";
                    String username = request.getParameter(USER_NAME);
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                    }

                    redirectURL = loginPage + ("?" + queryParams) + BasicAuthenticatorConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants
                            .AUTHENTICATORS + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam;
                    setAuthenticatorErrorMessage(getErrorMessage(errorCode, ACCOUNT_CONFIRMATION_PENDING), context);
                } else if (errorCode.equals(IdentityCoreConstants.USER_EMAIL_NOT_VERIFIED_ERROR_CODE)
                            || errorCode.equals(IdentityCoreConstants.USER_EMAIL_OTP_NOT_VERIFIED_ERROR_CODE)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "email.verification.pending";
                    if (errorCode.equals(IdentityCoreConstants.USER_EMAIL_OTP_NOT_VERIFIED_ERROR_CODE)) {
                        retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                                BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "email.otp.verification.pending";
                    }
                    String username = request.getParameter(USER_NAME);
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                    }
                    redirectURL = loginPage + ("?" + queryParams) + BasicAuthenticatorConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants
                            .AUTHENTICATORS + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam;
                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "password.reset.pending";
                    if (Boolean.parseBoolean(maskAdminForcedPasswordResetErrorCode)) {

                        errorCode = UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;
                        if (log.isDebugEnabled()) {
                            log.debug("Masking password reset pending error code: " +
                                    IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE +
                                    " with error code: " + errorCode);
                        }
                        retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                    }
                    redirectURL = loginPage + ("?" + queryParams) +
                            BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(request.getParameter(
                            USER_NAME), BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode +
                            BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL + retryParam;

                    setAuthenticatorErrorMessage(getErrorMessage(errorCode,
                            FORCED_PASSWORD_RESET_VIA_EMAIL), context);
                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE)) {
                    String username = request.getParameter(USER_NAME);
                    String tenantDomain = getTenantDomainFromUserName(context, username);

                    // Setting callback so that the user is prompted to login after a password reset.
                    String callback;
                    try {
                        callback = ServiceURLBuilder.create().addPath(loginPage).build().getAbsolutePublicURL();
                    } catch (URLBuilderException e) {
                        throw new IdentityRuntimeException(
                                "Error while building callback url for context: " + loginPage, e);
                    }
                    callback = callback + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL;
                    String reason = RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name();

                    redirectURL = recoveryPage + CONFIRM_RECOVERY_DO +
                            BasicAuthenticatorConstants.USER_NAME_PARAM + URLEncoder.encode(username,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM +
                            URLEncoder.encode(tenantDomain, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(password,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.CALLBACK_PARAM +
                            URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.REASON_PARAM +
                            URLEncoder.encode(reason, BasicAuthenticatorConstants.UTF_8);
                    setAuthenticatorErrorMessage(getErrorMessage(errorCode, FORCED_PASSWORD_RESET_VIA_OTP),
                            context);
                } else if (errorCode.equals(IdentityCoreConstants.ASK_PASSWORD_SET_PASSWORD_VIA_OTP_ERROR_CODE)) {
                    String username = request.getParameter(USER_NAME);
                    String tenantDomain = getTenantDomainFromUserName(context, username);

                    // Setting callback so that the user is prompted to login after setting password.
                    String callback;
                    try {
                        callback = ServiceURLBuilder.create().addPath(loginPage).build().getAbsolutePublicURL();
                    } catch (URLBuilderException e) {
                        throw new IdentityRuntimeException(
                                "Error while building callback url for context: " + loginPage, e);
                    }
                    callback = callback + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL;
                    String reason = RecoveryScenarios.ASK_PASSWORD_VIA_EMAIL_OTP.name();

                    String recoveryPortalPath = getRecoveryPortalPath(tenantDomain,
                            Constants.FlowTypes.INVITED_USER_REGISTRATION.getType());
                    redirectURL = recoveryPortalPath +
                            BasicAuthenticatorConstants.USER_NAME_PARAM + URLEncoder.encode(username,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM +
                            URLEncoder.encode(tenantDomain, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(password,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.CALLBACK_PARAM +
                            URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.REASON_PARAM +
                            URLEncoder.encode(reason, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.TYPE_PARAM + BasicAuthenticatorConstants.INVITE;
                    setAuthenticatorErrorMessage(getErrorMessage(errorCode, ASK_PASSWORD_VIA_OTP), context);
                } else if (errorCode.equals(
                        IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "account.pending.approval";
                    String username = request.getParameter(USER_NAME);

                    redirectURL = loginPage + ("?" + queryParams) + BasicAuthenticatorConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants
                            .AUTHENTICATORS + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam;
                    setAuthenticatorErrorMessage(getErrorMessage(errorCode, ACCOUNT_PENDING_APPROVAL), context);
                } else if ("true".equals(showAuthFailureReason)) {

                    if (Boolean.parseBoolean(maskUserNotExistsErrorCode) &&
                            StringUtils.contains(errorCode, UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {

                        errorCode = UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;

                        if (log.isDebugEnabled()) {
                            log.debug("Masking user not found error code: " +
                                    UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST + " with error code: " +
                                    errorCode);
                        }
                        setAuthenticatorErrorMessage(getErrorMessage(errorCode, INVALID_CREDENTIALS_ARE_PROVIDED),
                                context);
                    }

                    String reason = null;
                    if (errorCode.contains(":")) {
                        String[] errorCodeReason = errorCode.split(":", 2);
                        errorCode = errorCodeReason[0];
                        if (errorCodeReason.length > 1) {
                            reason = errorCodeReason[1];
                        }
                    }
                    int remainingAttempts =
                            errorContext.getMaximumLoginAttempts() - errorContext.getFailedLoginAttempts();

                    if (log.isDebugEnabled()) {
                        log.debug("errorCode : " + errorCode);
                        log.debug("username : " + request.getParameter(USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));
                        paramMap.put(BasicAuthenticatorConstants.REMAINING_ATTEMPTS, String.valueOf(remainingAttempts));

                        retryParam = retryParam + buildErrorParamString(paramMap, omittingErrorParams);
                        redirectURL = loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam;
                        Map<String, String> messageContext = getMessageContext(REMAINING_ATTEMPTS,
                                String.valueOf(remainingAttempts));
                        setAuthenticatorErrorMessage(new AuthenticatorMessage
                                (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                                        INVALID_CREDENTIALS_ARE_PROVIDED, messageContext), context);
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));

                        if (StringUtils.isNotBlank(reason)) {
                            paramMap.put(BasicAuthenticatorConstants.LOCKED_REASON, reason);
                        }
                        if (remainingAttempts == 0) {
                            paramMap.put(BasicAuthenticatorConstants.REMAINING_ATTEMPTS, "0");
                        }
                        if (Boolean.parseBoolean(showAuthFailureReasonOnLoginPage)) {
                            redirectURL = loginPage + ("?" + queryParams)
                                    + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                    BasicAuthenticatorConstants.LOCAL + buildErrorParamString(paramMap, omittingErrorParams);
                        } else {
                            redirectURL = response.encodeRedirectURL(retryPage + ("?" + queryParams))
                                    + buildErrorParamString(paramMap, omittingErrorParams);
                        }
                        Map<String, String> messageContext = getMessageContext(ACCOUNT_LOCKED_REASON,
                                String.valueOf(reason));
                        setAuthenticatorErrorMessage(new AuthenticatorMessage
                                (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                                        ACCOUNT_IS_LOCKED, messageContext),
                                context);
                    } else if (errorCode.equals(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));

                        retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                        redirectURL = loginPage + ("?" + queryParams)
                                + buildErrorParamString(paramMap, omittingErrorParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam;
                        setAuthenticatorErrorMessage(getErrorMessage(errorCode, OTP_MISMATCH_IN_ADMIN_FORCED_PASSWORD_RESET),
                                context);
                    } else {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        if (request.getParameter(USER_NAME) != null) {
                            paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                    URLEncoder.encode(request.getParameter(USER_NAME),
                                            BasicAuthenticatorConstants.UTF_8));
                        }
                        if (StringUtils.isNotBlank(reason)) {
                            retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                                    BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + URLEncoder.encode(reason,
                                    BasicAuthenticatorConstants.UTF_8);
                        }
                        retryParam = retryParam + buildErrorParamString(paramMap, omittingErrorParams);
                        redirectURL = loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicAuthenticatorConstants.LOCAL + retryParam;
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                    redirectURL = loginPage + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL + retryParam;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                redirectURL = loginPage + ("?" + queryParams)
                        + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                        BasicAuthenticatorConstants.LOCAL + retryParam;
            }

            int failedLoginAttempts = errorContext == null ? 0 : errorContext.getFailedLoginAttempts();
            redirectURL += getCaptchaParams(context.getLoginTenantDomain(), failedLoginAttempts);
            response.sendRedirect(redirectURL);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        BasicAuthenticatorConstants.LogConstants.BASIC_AUTH_SERVICE,
                        BasicAuthenticatorConstants.LogConstants.ActionIDs.VALIDATE_BASIC_AUTH_REQUEST);
                diagnosticLogBuilder.resultMessage("Redirecting to the basic auth login page.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep());
                getApplicationDetails(context, diagnosticLogBuilder);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                    e.getMessage(),
                    User.getUserFromUserName(request.getParameter(USER_NAME)), e);
        }
    }

    private static Map<String, String> getMessageContext(String key, String value) {

        Map <String,String> messageContext = new HashMap<>();
        messageContext.put(key, value);
        return messageContext;
    }

    private static AuthenticatorMessage getErrorMessage(String errorCode, String accountConfirmationPending) {

        return new AuthenticatorMessage
                (FrameworkConstants.AuthenticatorMessageType.ERROR, errorCode,
                        accountConfirmationPending, null);
    }

    private static void setAuthenticatorErrorMessage(AuthenticatorMessage errorMessage, AuthenticationContext context) {

        context.setProperty(AUTHENTICATOR_MESSAGE, errorMessage);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BasicAuthenticatorConstants.LogConstants.BASIC_AUTH_SERVICE,
                    BasicAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing basic authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam("current auth step", context.getCurrentStep());
            getApplicationDetails(context, diagnosticLogBuilder);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String captchaParamString = getCaptchaParams(context.getLoginTenantDomain(), 0);
        if (StringUtils.isNotBlank(captchaParamString)) {
            context.setProperty(FrameworkConstants.CAPTCHA_PARAM_STRING, captchaParamString);
        }
        Map<String, String> runtimeParams = getRuntimeParams(context);
        String loginIdentifierFromRequest = request.getParameter(USER_NAME);
        if (StringUtils.isBlank(loginIdentifierFromRequest) &&
                Boolean.TRUE.equals(context.getProperty(RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS))) {
            loginIdentifierFromRequest = runtimeParams.get(USER_NAME);
        }
        if (StringUtils.isBlank(loginIdentifierFromRequest)) {
            throw new InvalidCredentialsException(ErrorMessages.EMPTY_USERNAME.getCode(),
                    ErrorMessages.EMPTY_USERNAME.getMessage());
        }
        context.setProperty(USERNAME_USER_INPUT, loginIdentifierFromRequest);
        if (runtimeParams != null) {
            // FrameworkUtils.preprocessUsername will not append the tenant domain to username, if you are using
            // email as username and EnableEmailUserName config is not enabled. So for a SaaS app, this config needs
            // to be enabled to add the tenant domain to email username if EnableEmailUserName is not enabled in the
            // system.
            String appendUserTenant = runtimeParams.get(APPEND_USER_TENANT_TO_USERNAME);
            if (Boolean.parseBoolean(appendUserTenant)) {
                loginIdentifierFromRequest = loginIdentifierFromRequest + "@" + context.getUserTenantDomain();
            }

            /** FrameworkUtils.preprocessUsername will not append the tenant domain to username, if you are using
             * email as username and EnableEmailUserName config is not enabled. So for a SaaS app, this config needs
             * to be enabled to add the tenant domain of the application to email username if EnableEmailUserName
             * is not enabled in the system.
             **/
            String appendAppTenant = runtimeParams.get(APPEND_APP_TENANT_TO_USERNAME);
            if (Boolean.parseBoolean(appendAppTenant)) {
                loginIdentifierFromRequest = loginIdentifierFromRequest + "@" + context.getTenantDomain();
            }
        }

        String username = FrameworkUtils.preprocessUsername(loginIdentifierFromRequest, context);
        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
            FrameworkUtils.validateUsername(loginIdentifierFromRequest, context);
        }
        String requestTenantDomain = MultitenantUtils.getTenantDomain(username);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userId = null;
        if (BasicAuthenticatorDataHolder.getInstance().getMultiAttributeLogin().isEnabled(requestTenantDomain)) {
            ResolvedUserResult resolvedUserResult = BasicAuthenticatorDataHolder.getInstance().getMultiAttributeLogin().
                    resolveUser(tenantAwareUsername, requestTenantDomain);
            if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.
                    equals(resolvedUserResult.getResolvedStatus())) {
                tenantAwareUsername = resolvedUserResult.getUser().getUsername();
                username = UserCoreUtil.addTenantDomainToEntry(tenantAwareUsername, requestTenantDomain);
                userId = resolvedUserResult.getUser().getUserID();
            } else {
                context.setProperty(IS_INVALID_USERNAME, true);
                validateUserTenantDomain(context, requestTenantDomain);
                throw new InvalidCredentialsException(ErrorMessages.USER_DOES_NOT_EXISTS.getCode(),
                        ErrorMessages.USER_DOES_NOT_EXISTS.getMessage(), User.getUserFromUserName(username));
            }
        }
        String password = request.getParameter(PASSWORD);
        if (StringUtils.isBlank(password) &&
                Boolean.TRUE.equals(context.getProperty(RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS))) {
            password = runtimeParams.get(PASSWORD);
            context.removeProperty(RESOLVE_CREDENTIALS_FROM_RUNTIME_PARAMS);
        }
        if (StringUtils.isBlank(password)) {
            throw new InvalidCredentialsException(ErrorMessages.EMPTY_PASSWORD.getCode(),
                    ErrorMessages.EMPTY_PASSWORD.getMessage());
        }
        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        if (runtimeParams != null) {
            String usernameFromContext = runtimeParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
            /*
             * Check whether Username set for identifier first login and username submitted from
             * login page does not match. If the username submitted by login page is null, then the
             * username from the context will be considered as the username submitted from the login page.
             */
            String requestUsername = request.getParameter(USER_NAME);
            String requestUsernameWithTenant = null;
            if (StringUtils.isNotBlank(requestUsername)) {
                requestUsernameWithTenant =
                        UserCoreUtil.addTenantDomainToEntry(requestUsername, requestTenantDomain);
            }
            if (requestUsername != null && usernameFromContext != null &&
                    !usernameFromContext.equals(requestUsername) &&
                    !usernameFromContext.equals(requestUsernameWithTenant)) {
                if (log.isDebugEnabled()) {
                    log.debug("Username set for identifier first login: " + usernameFromContext + " and username " +
                            "submitted from login page" + username + " does not match.");
                }
                throw new InvalidCredentialsException(ErrorMessages.CREDENTIAL_MISMATCH.getCode(),
                        ErrorMessages.CREDENTIAL_MISMATCH.getMessage());
            }
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        boolean isAuthenticated = false;
        AbstractUserStoreManager userStoreManager = getUserStoreManager(username, requestTenantDomain);
        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        AuthenticationResult authenticationResult;
        try {
            setUserExistThreadLocal();

            if (userId != null) {
                authenticationResult = userStoreManager.authenticateWithID(userId, password);
            } else {
                authenticationResult = userStoreManager.authenticateWithID(UserCoreClaimConstants.USERNAME_CLAIM_URI,
                        tenantAwareUsername, password, UserCoreConstants.DEFAULT_PROFILE);
            }
            if (AuthenticationResult.AuthenticationStatus.SUCCESS == authenticationResult.getAuthenticationStatus()
                    && authenticationResult.getAuthenticatedUser().isPresent()) {
                isAuthenticated = true;
                context.removeProperty(FrameworkConstants.CAPTCHA_PARAM_STRING);
            }
            if (isAuthPolicyAccountExistCheck()) {
                checkUserExistence();
            }
        } catch (UserStoreClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate the user " + username, e);
            }
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(e.getErrorCode() +
                    ":" + e.getMessage());
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                    User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate the user " + username, e);
            }
            // Sometimes client exceptions are wrapped in the super class.
            // Therefore checking for possible client exception.
            Throwable rootCause = ExceptionUtils.getRootCause(e);
            if (rootCause instanceof UserStoreClientException) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        ((UserStoreClientException) rootCause).getErrorCode() + ":" + rootCause.getMessage());
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }

            boolean showPendingUserInfo = showPendingUserInformationDefaultConfig();
            try {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(IdentityTenantUtil.getTenantId
                        (requestTenantDomain));
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(requestTenantDomain);
                String tenantWiseConfig = BasicAuthenticatorDataHolder.getInstance()
                        .getConfigurationManager().getAttribute(RESOURCE_TYPE_NAME_CONFIG, RESOURCE_NAME_CONFIG,
                                PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG).getValue();
                if (StringUtils.isNotBlank(tenantWiseConfig)) {
                    showPendingUserInfo = Boolean.parseBoolean(tenantWiseConfig);
                }
            } catch (ConfigurationManagementException configException) {
                if (ERROR_CODE_FEATURE_NOT_ENABLED.getCode().equals(configException.getErrorCode())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("%s Therefore using the default configuration value: %s for the " +
                                        "attribute: %s", ERROR_CODE_FEATURE_NOT_ENABLED.getMessage(), showPendingUserInfo,
                                PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG));
                    }
                } else if (ERROR_CODE_ATTRIBUTE_DOES_NOT_EXISTS.getCode().equals(configException.getErrorCode())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("%s attribute doesn't exist for the tenant: %s. Therefore using the " +
                                        "default configuration value: %s for the attribute: %s",
                                PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG, requestTenantDomain,
                                showPendingUserInfo, PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG));
                    }
                } else if (ERROR_CODE_RESOURCE_TYPE_DOES_NOT_EXISTS.getCode().equals(configException.getErrorCode())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("%s resource type doesn't exist for the tenant: %s. Therefore using " +
                                        "the default configuration value: %s for the attribute: %s",
                                RESOURCE_TYPE_NAME_CONFIG, requestTenantDomain, showPendingUserInfo,
                                PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG));
                    }
                } else if (ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode().equals(configException.getErrorCode())) {
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("%s resource doesn't exist for the tenant: %s. Therefore using the " +
                                        "default configuration value: %s for the attribute: %s", RESOURCE_NAME_CONFIG,
                                requestTenantDomain, showPendingUserInfo,
                                PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG));
                    }
                } else {
                    throw new AuthenticationFailedException(String.format("Error in retrieving %s configuration for " +
                            "the tenant %s", PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG, requestTenantDomain, e));
                }
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
            if (showPendingUserInfo) {
                throw new AuthenticationFailedException(
                        ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                        User.getUserFromUserName(username), e);
            } else {
                throw new AuthenticationFailedException(
                        ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                        e);
            }
        } finally {
            clearUserExistThreadLocal();
        }

        if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }
            if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                username = IdentityUtil.addDomainToName(
                        username, IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN).toString());
            }
            IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);

            IdentityErrorMsgContext errorContext = IdentityUtil.getIdentityErrorMsg();
            int failedLoginAttempts = errorContext == null ? 0 : errorContext.getFailedLoginAttempts();
            captchaParamString = getCaptchaParams(context.getLoginTenantDomain(), failedLoginAttempts);
            if (StringUtils.isNotBlank(captchaParamString)) {
                context.setProperty(FrameworkConstants.CAPTCHA_PARAM_STRING, captchaParamString);
            }
            validateUserTenantDomain(context, requestTenantDomain);
            throw new InvalidCredentialsException(ErrorMessages.INVALID_CREDENTIALS.getCode(),
                    ErrorMessages.INVALID_CREDENTIALS.getMessage(), User.getUserFromUserName(username));
        }

        //TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", requestTenantDomain);


        AuthenticatedUser authenticatedUser = new AuthenticatedUser(authenticationResult.getAuthenticatedUser().get());

        // Update the username from the deprecated multi attribute login feature.
        updateMultiAttributeUsername(authenticatedUser, userStoreManager);
        authenticatedUser.setAuthenticatedSubjectIdentifier(authenticatedUser.getUsernameAsSubjectIdentifier(true, true));
        context.setSubject(authenticatedUser);

        String rememberMe = request.getParameter("chkRemember");
        if ("on".equals(rememberMe)) {
            context.setRememberMe(true);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    BasicAuthenticatorConstants.LogConstants.BASIC_AUTH_SERVICE,
                    BasicAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Basic authentication response process completed.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParam("remember me", context.isRememberMe());
            getApplicationDetails(context, diagnosticLogBuilder);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
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
        return BasicAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return BasicAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    private String buildErrorParamString(Map<String, String> paramMap, List<String> omittingErrorParams) {

        StringBuilder params = new StringBuilder();
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            params.append(filterAndAddParam(entry.getKey(), entry.getValue(), omittingErrorParams));
        }
        return params.toString();
    }

    private String filterAndAddParam(String key, String value, List<String> omittingErrorParams) {

        String keyActual = key.replaceAll("&", "").replaceAll("=", "");
        if (CollectionUtils.isNotEmpty(omittingErrorParams) && omittingErrorParams.contains(keyActual)) {
            if (log.isDebugEnabled()) {
                log.debug("omitting param " + keyActual + " in the error response.");
            }

            // The param should be omitted, hence returning empty string.
            return StringUtils.EMPTY;
        } else {
            return key + value;
        }
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for the authentication always.
     *
     * @param tenantDomain        Tenant domain of the application.
     * @param failedLoginAttempts Number of failed login attempts.
     * @return string with the appended recaptcha params
     */
    private String getCaptchaParams(String tenantDomain, int failedLoginAttempts) {

        SSOLoginReCaptchaConfig connector = new SSOLoginReCaptchaConfig();
        String defaultCaptchaConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;
        String maxFailedAttemptCaptchaConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.MAX_ATTEMPTS;
        String captchaEnabledConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE;
        String captchaParams = "";
        Property[] connectorConfigs;
        Properties captchaConfigs = getCaptchaConfigs();

        if (captchaConfigs != null && !captchaConfigs.isEmpty() &&
                Boolean.parseBoolean(captchaConfigs.getProperty(CaptchaConstants.RE_CAPTCHA_ENABLED))) {

            boolean forcefullyEnabledRecaptchaForAllTenants = Boolean.parseBoolean(captchaConfigs.getProperty(
                    CaptchaConstants.FORCEFULLY_ENABLED_RECAPTCHA_FOR_ALL_TENANTS));
            try {
                connectorConfigs = BasicAuthenticatorDataHolder.getInstance().getIdentityGovernanceService()
                        .getConfiguration(new String[]{defaultCaptchaConfigName, RESEND_CONFIRMATION_RECAPTCHA_ENABLE,
                                captchaEnabledConfigName}, tenantDomain);
                for (Property connectorConfig : connectorConfigs) {
                    if (defaultCaptchaConfigName.equals(connectorConfig.getName())) {
                        // SSO Login Captcha Config
                        if (Boolean.parseBoolean(connectorConfig.getValue()) ||
                                forcefullyEnabledRecaptchaForAllTenants) {
                            captchaParams = BasicAuthenticatorConstants.RECAPTCHA_PARAM + "true";
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Enforcing recaptcha for SSO Login is not enabled.");
                            }
                        }
                    } else if ((RESEND_CONFIRMATION_RECAPTCHA_ENABLE).equals(connectorConfig.getName())) {
                        // Resend Confirmation Captcha Config
                        if (Boolean.parseBoolean(connectorConfig.getValue()) ||
                                forcefullyEnabledRecaptchaForAllTenants) {
                            captchaParams += BasicAuthenticatorConstants.RECAPTCHA_RESEND_CONFIRMATION_PARAM + "true";
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Enforcing recaptcha for resend confirmation is not enabled.");
                            }
                        }
                    } else if (captchaEnabledConfigName.equals(connectorConfig.getName())) {
                        if (!Boolean.parseBoolean(connectorConfig.getValue())) {
                            if (log.isDebugEnabled()) {
                                log.debug("Enforcing recaptcha for exceeding max failed login is not enabled.");
                            }
                            continue;
                        }
                        Property[] maxFailedConfig =
                                BasicAuthenticatorDataHolder.getInstance().getIdentityGovernanceService()
                                        .getConfiguration(new String[]{maxFailedAttemptCaptchaConfigName},
                                                tenantDomain);
                        Property maxFailedProperty = maxFailedConfig[0];
                        int maxFailedAttempts;
                        if (NumberUtils.isNumber(maxFailedProperty.getValue())) {
                            maxFailedAttempts = Integer.valueOf(maxFailedProperty.getValue());
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug(String.format("Invalid value for Max failed attempts for reCaptcha: %s. " +
                                        "Default value will be used.", maxFailedProperty.getValue()));
                            }
                            // Setting up default value for max failed login attempts before reCaptcha.
                            maxFailedAttempts = 3;
                        }
                        if (maxFailedAttempts >= failedLoginAttempts) {
                            if (log.isDebugEnabled()) {
                                log.debug("Number of failed attempts is less than or equal to max failed " +
                                        "login attempts before reCaptcha. Recaptcha will not be enforced.");
                            }
                            continue;
                        }
                        if (log.isDebugEnabled()) {
                            log.debug("Number of failed attempts is higher than max failed login" +
                                    "attempts before reCaptcha. Recaptcha will be enforced.");
                        }
                        captchaParams += BasicAuthenticatorConstants.RECAPTCHA_PARAM + "true";
                    }
                }

            } catch (IdentityGovernanceException e) {
                log.error("Error occurred while verifying the captcha configs. Proceeding the authentication request " +
                        "without enabling recaptcha.", e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Recaptcha is not enabled.");
            }
        }

        return captchaParams;
    }

    /**
     * Get the recaptcha configs from the data holder if they are valid.
     *
     * @return recaptcha properties
     */
    private Properties getCaptchaConfigs() {

        Properties properties = BasicAuthenticatorDataHolder.getInstance().getRecaptchaConfigs();

        if (properties != null && !properties.isEmpty() &&
                Boolean.valueOf(properties.getProperty(CaptchaConstants.RE_CAPTCHA_ENABLED))) {
            if (StringUtils.isBlank(properties.getProperty(CaptchaConstants.RE_CAPTCHA_SITE_KEY)) ||
                    StringUtils.isBlank(properties.getProperty(CaptchaConstants.RE_CAPTCHA_API_URL)) ||
                    StringUtils.isBlank(properties.getProperty(CaptchaConstants.RE_CAPTCHA_SECRET_KEY)) ||
                    StringUtils.isBlank(properties.getProperty(CaptchaConstants.RE_CAPTCHA_VERIFY_URL))) {

                if (log.isDebugEnabled()) {
                    log.debug("Empty values found for the captcha properties in the file " + CaptchaConstants
                            .CAPTCHA_CONFIG_FILE_NAME + ".");
                }
                properties.clear();
            }
        }
        return properties;
    }

    private void updateMultiAttributeUsername(AuthenticatedUser user, AbstractUserStoreManager userStoreManager) {

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String userNameUri = getAuthenticatorConfig().getParameterMap().get("UserNameAttributeClaimUri");
            if (StringUtils.isNotBlank(userNameUri)) {
                String domain = UserCoreUtil.getDomainFromThreadLocal();
                boolean multipleAttributeEnable = isMultipleAttributeEnable(userStoreManager, domain);
                if (multipleAttributeEnable) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Searching for UserNameAttribute value for user " + user.getLoggableUserId() +
                                    " for claim uri : " + userNameUri);
                        }
                        // This getUserClaimValue cannot be converted to user id method, since if the value user
                        // enters is not the actual username, user id will not be available in AuthenticationResult.
                        String usernameValue = getMultiAttributeUsername(user, userStoreManager, userNameUri);
                        if (StringUtils.isNotBlank(usernameValue)) {
                            user.setUserName(usernameValue);
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user + " + user.getLoggableUserId()
                                        + ". Value is: " + usernameValue);
                            }
                        }
                    } catch (UserStoreException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Error while retrieving UserNameAttribute for user : " +
                                    user.getLoggableUserId(), e);
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("MultipleAttribute is not enabled for user store domain : " + domain + " " +
                                "Therefore UserNameAttribute is not retrieved");
                    }
                }
            }
        }
    }

    private String getMultiAttributeUsername(AuthenticatedUser user, AbstractUserStoreManager userStoreManager,
                                             String userNameUri) throws UserStoreException {

        String usernameValue;
        if (user.getUserStoreDomain() != null
                && !UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equals(user.getUserStoreDomain())) {
            usernameValue =
                    userStoreManager.getSecondaryUserStoreManager(user.getUserStoreDomain())
                            .getUserClaimValue(user.getUserName(), userNameUri, null);
        } else {
            usernameValue = userStoreManager.
                    getUserClaimValue(user.getUserName(), userNameUri, null);
        }
        return usernameValue;
    }

    /**
     * Check if the ldap based multi attribute login is enabled.
     *
     * @param userStoreManager Primary user store manager.
     * @param domain           user store domain.
     * @return if multi attributed enabled.
     */
    private boolean isMultipleAttributeEnable(AbstractUserStoreManager userStoreManager, String domain) {

        boolean multipleAttributeEnable;
        if (StringUtils.isNotBlank(domain)) {
            multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.getSecondaryUserStoreManager(domain)
                    .getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
        } else {
            multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.
                    getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
        }
        return multipleAttributeEnable;
    }

    private AbstractUserStoreManager getUserStoreManager(String username, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            int tenantId =
                    BasicAuthenticatorServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            UserRealm userRealm = BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                return (AbstractUserStoreManager) userRealm.getUserStoreManager();
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Can't find the UserStoreManager for the user: " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private boolean isAuthPolicyAccountExistCheck() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(BasicAuthenticatorConstants.AUTHENTICATION_POLICY_CONFIG));
    }

    /**
     * Check user existence and set error code to IdentityErrorMsgContext if user does not exist.
     */
    private void checkUserExistence() {

        if (!isUserExist()) {
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                    .ErrorCode.USER_DOES_NOT_EXIST);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
        }
    }

    private Boolean isUserExist() {

        return IdentityUtil.threadLocalProperties.get().get(USER_EXIST_THREAD_LOCAL_PROPERTY) != null &&
                (Boolean) IdentityUtil.threadLocalProperties.get().get(USER_EXIST_THREAD_LOCAL_PROPERTY);
    }

    private void setUserExistThreadLocal() {

        IdentityUtil.threadLocalProperties.get().put(USER_EXIST_THREAD_LOCAL_PROPERTY, false);
        if (log.isDebugEnabled()) {
            log.debug(USER_EXIST_THREAD_LOCAL_PROPERTY + " is added as false to thread local.");
        }
    }

    private void clearUserExistThreadLocal() {

        IdentityUtil.threadLocalProperties.get().remove(USER_EXIST_THREAD_LOCAL_PROPERTY);
    }

    private String getTenantDomainFromUserName(AuthenticationContext context, String username) {

        boolean isSaaSApp = context.getSequenceConfig().getApplicationConfig().isSaaSApp();
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && !isSaaSApp) {
            return IdentityTenantUtil.getTenantDomainFromContext();
        }
        return MultitenantUtils.getTenantDomain(username);
    }

    private boolean isURLContainSensitiveData(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationContext context) throws AuthenticationFailedException {

        String queryString;
        if (request instanceof AuthenticationFrameworkWrapper) {
            queryString = ((HttpServletRequest) ((AuthenticationFrameworkWrapper) request).getRequest())
                    .getQueryString();
        } else {
            queryString = request.getQueryString();
        }

        if (StringUtils.contains(queryString, USER_NAME + "=") ||
                StringUtils.contains(queryString, PASSWORD + "=")) {

            String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            String queryParams = context.getContextIdIncludedQueryParams();
            String redirectURL = loginPage + "?" + queryParams + BasicAuthenticatorConstants.AUTHENTICATORS +
                    getName() + ":" + BasicAuthenticatorConstants.LOCAL +
                    BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                    BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "query.params.contains.user.credentials";
            try {
                response.sendRedirect(redirectURL);
            } catch (IOException e) {
                throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                        e.getMessage(),
                        User.getUserFromUserName(request.getParameter(USER_NAME)), e);
            }
            return true;
        }
        return false;
    }

    private boolean showPendingUserInformationDefaultConfig() {

        String showPendingUserInformation = IdentityUtil.getProperty(SHOW_PENDING_USER_INFORMATION_CONFIG);
        if (showPendingUserInformation == null) {
            return SHOW_PENDING_USER_INFORMATION_DEFAULT_VALUE;
        } else {
            return Boolean.parseBoolean(showPendingUserInformation);
        }
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
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            AuthenticatorMessage authenticatorMessage = (AuthenticatorMessage) context.getProperty
                    (AUTHENTICATOR_MESSAGE);
            authenticatorData.setMessage(authenticatorMessage);
        }

        authenticatorData.setName(getName());
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setIdp(idpName);
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        setAuthParams(authenticatorData);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(USER_NAME);
        requiredParams.add(PASSWORD);
        authenticatorData.setRequiredParams(requiredParams);

        return Optional.of(authenticatorData);
    }

    private static void setAuthParams(AuthenticatorData authenticatorData) {

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USER_NAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, BasicAuthenticatorConstants.USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);
        AuthenticatorParamMetadata passwordMetadata = new AuthenticatorParamMetadata(
                PASSWORD, DISPLAY_PASSWORD, FrameworkConstants.AuthenticatorParamType.STRING,
                1, Boolean.TRUE, BasicAuthenticatorConstants.PASSWORD_PARAM);
        authenticatorParamMetadataList.add(passwordMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
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

    /** Add application details to diagnosticLogBuilder.
     *
     * @param context AuthenticationContext.
     * @param diagnosticLogBuilder DiagnosticLogBuilder.
     */
    private void getApplicationDetails(AuthenticationContext context,
                                                      DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder) {

        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));

    }

    /**
     * Set i18nKey.
     *
     * @return the i18n key
     */
    @Override
    public String getI18nKey() {

        return AUTHENTICATOR_BASIC;
    }

    private String getRecoveryPortalPath(String tenantDomain, String flowType) {

        try {
            if (FlowMgtConfigUtils.getFlowConfig(flowType, tenantDomain).getIsEnabled()) {
                try {
                    String configuredPortalURL = BrandingPreferenceMgtUtils.buildConfiguredPortalURL(null,
                            tenantDomain,
                            BasicAuthenticatorDataHolder.getInstance().getBrandingPreferenceManager(), flowType);
                    return String.format("%s?flowType=%s&", configuredPortalURL, flowType);
                } catch (BrandingPreferenceMgtException | URLBuilderException e) {
                    log.error("Error while retrieving the portal URL for flowtype: " + flowType, e);
                }
            }
        } catch (FlowMgtServerException e) {
            log.error("Error while retrieving the flow configuration for " + flowType +  " flow.", e);
        }
        return ConfigurationFacade.getInstance().getAccountRecoveryEndpointPath() + CONFIRM_RECOVERY_DO;
    }

    private void validateUserTenantDomain(AuthenticationContext context, String userTenantDomain) {

        String contextTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (StringUtils.equalsIgnoreCase(userTenantDomain, contextTenantDomain)) {
            return;
        }

        log.warn("Tenant domain mismatch detected during authentication failure. User Tenant Domain: "
                + userTenantDomain + ", Request Tenant Domain: " + contextTenantDomain + ", isSaasApp: "
                + context.getSequenceConfig().getApplicationConfig().isSaaSApp());
    }
}
