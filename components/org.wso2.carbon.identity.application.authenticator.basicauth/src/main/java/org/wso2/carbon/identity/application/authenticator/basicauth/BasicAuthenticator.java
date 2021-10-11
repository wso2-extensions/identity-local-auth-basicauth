/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.BasicAuthErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.captcha.connector.recaptcha.SSOLoginReCaptchaConfig;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.multi.attribute.login.mgt.ResolvedUserResult;
import org.wso2.carbon.identity.recovery.RecoveryScenarios;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.util.AutoLoginConstant;

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

/**
 * Username Password based Authenticator.
 */
public class BasicAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 1819664539416029785L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String PASSWORD_RESET_ENDPOINT = "accountrecoveryendpoint/confirmrecovery.do?";
    private static final Log log = LogFactory.getLog(BasicAuthenticator.class);
    private static final String RESEND_CONFIRMATION_RECAPTCHA_ENABLE = "SelfRegistration.ResendConfirmationReCaptcha";
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";
    private List<String> omittingErrorParams = null;

    /**
     * USER_EXIST_THREAD_LOCAL_PROPERTY is used to maintain the state of user existence
     * which has used in org.wso2.carbon.identity.governance.listener.IdentityMgtEventListener.
     */
    private static String USER_EXIST_THREAD_LOCAL_PROPERTY = "userExistThreadLocalProperty";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);
        Cookie autoLoginCookie = getAutoLoginCookie(request.getCookies());

        return (userName != null && password != null) || autoLoginCookie != null;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        Cookie autoLoginCookie = getAutoLoginCookie(request.getCookies());

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (autoLoginCookie != null && isEnableAutoLoginEnabled(context, autoLoginCookie)) {
            try {
                return executeAutoLoginFlow(request, response, context, autoLoginCookie);
            } catch (AuthenticationFailedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while executing the Auto Login from Cookie flow: " + e);
                }
                removeAutoLoginCookie(response, autoLoginCookie);
            }
        }
        return super.process(request, response, context);
    }

    protected AuthenticatorFlowStatus executeAutoLoginFlow(HttpServletRequest request, HttpServletResponse response,
                                                         AuthenticationContext context, Cookie autoLoginCookie)
            throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(autoLoginCookie.getValue()));
        JSONObject cookieValueJSON = transformToJSON(decodedValue);
        String usernameInCookie = (String) cookieValueJSON.get(AutoLoginConstant.USERNAME);
        String signature = (String) cookieValueJSON.get(AutoLoginConstant.SIGNATURE);
        String content = usernameInCookie;
        String alias = null;
        if (StringUtils.isEmpty(usernameInCookie)) {
            content = (String) cookieValueJSON.get(AutoLoginConstant.CONTENT);
            JSONObject contentJSON = transformToJSON(content);
            usernameInCookie = (String) contentJSON.get(AutoLoginConstant.USERNAME);
            alias = getSelfRegistrationAutoLoginAlias(context);
        }

        String usernameInHttpRequest = request.getParameter(AutoLoginConstant.USERNAME);

        if (log.isDebugEnabled()) {
            log.debug("Started executing Auto Login from Cookie flow.");
        }

        if (StringUtils.isNotEmpty(usernameInHttpRequest) && StringUtils.isNotEmpty(usernameInCookie) &&
                !StringUtils.equalsIgnoreCase(usernameInHttpRequest, usernameInCookie)) {
            throw new AuthenticationFailedException("Username in HTTP Request: " + usernameInHttpRequest
                    + " and username in Cookie: " + usernameInCookie + " does not match.");
        }

        validateCookieSignature(content, signature, alias);
        usernameInCookie = FrameworkUtils.prependUserStoreDomainToName(usernameInCookie);

        String tenantDomain = MultitenantUtils.getTenantDomain(usernameInCookie);
        UserStoreManager userStoreManager = getUserStoreManager(usernameInCookie);

        usernameInCookie = getMultiAttributeUsername(usernameInCookie, tenantDomain, userStoreManager);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(usernameInCookie));
        removeAutoLoginCookie(response, autoLoginCookie);
        return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> parameterMap = getAuthenticatorConfig().getParameterMap();
        String showAuthFailureReason = null;
        String maskUserNotExistsErrorCode = null;
        String maskAdminForcedPasswordResetErrorCode = null;
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
        String retryPage = ConfigurationFacade.getInstance().getAuthenticationEndpointRetryURL();
        String queryParams = context.getContextIdIncludedQueryParams();
        String password = (String) context.getProperty(PASSWORD_PROPERTY);
        String redirectURL;
        context.getProperties().remove(PASSWORD_PROPERTY);

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (runtimeParams != null) {
            String inputType = null;
            String usernameFromContext = runtimeParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
            if (usernameFromContext != null) {
                inputType = FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST;
            }
            if (FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST.equalsIgnoreCase(inputType)) {
                queryParams += "&" + FrameworkConstants.RequestParams.INPUT_TYPE + "=" + inputType;
                context.addEndpointParam(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, usernameFromContext);
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
                    String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
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
                            BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode +
                            BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL + retryParam;

                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE)) {
                    String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
                    String tenantDoamin = MultitenantUtils.getTenantDomain(username);

                    // Setting callback so that the user is prompted to login after a password reset.
                    String callback = loginPage + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL;
                    String reason = RecoveryScenarios.ADMIN_FORCED_PASSWORD_RESET_VIA_OTP.name();

                    redirectURL = (PASSWORD_RESET_ENDPOINT + queryParams) +
                            BasicAuthenticatorConstants.USER_NAME_PARAM + URLEncoder.encode(username,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM +
                            URLEncoder.encode(tenantDoamin, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(password,
                            BasicAuthenticatorConstants.UTF_8) + BasicAuthenticatorConstants.CALLBACK_PARAM +
                            URLEncoder.encode(callback, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.REASON_PARAM +
                            URLEncoder.encode(reason, BasicAuthenticatorConstants.UTF_8);
                } else if (errorCode.equals(
                        IdentityCoreConstants.USER_ACCOUNT_PENDING_APPROVAL_ERROR_CODE)) {
                    retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                            BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + "account.pending.approval";
                    String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);

                    redirectURL = loginPage + ("?" + queryParams) + BasicAuthenticatorConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants
                            .AUTHENTICATORS + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam;
                } else if ("true".equals(showAuthFailureReason)) {

                    if (Boolean.parseBoolean(maskUserNotExistsErrorCode) &&
                            StringUtils.contains(errorCode, UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {

                        errorCode = UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;

                        if (log.isDebugEnabled()) {
                            log.debug("Masking user not found error code: " +
                                    UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST + " with error code: " +
                                    errorCode);
                        }
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
                        log.debug("username : " + request.getParameter(BasicAuthenticatorConstants.USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));
                        paramMap.put(BasicAuthenticatorConstants.REMAINING_ATTEMPTS, String.valueOf(remainingAttempts));

                        retryParam = retryParam + buildErrorParamString(paramMap);
                        redirectURL = loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam;

                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));

                        if (StringUtils.isNotBlank(reason)) {
                            paramMap.put(BasicAuthenticatorConstants.LOCKED_REASON, reason);
                        }
                        if (remainingAttempts == 0) {
                            paramMap.put(BasicAuthenticatorConstants.REMAINING_ATTEMPTS, "0");
                        }

                        redirectURL = response.encodeRedirectURL(retryPage + ("?" + queryParams))
                                + buildErrorParamString(paramMap);
                    } else if (errorCode.equals(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE)) {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));

                        retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                        redirectURL = loginPage + ("?" + queryParams)
                                + buildErrorParamString(paramMap)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam;

                    } else {
                        Map<String, String> paramMap = new HashMap<>();
                        paramMap.put(BasicAuthenticatorConstants.ERROR_CODE, errorCode);
                        paramMap.put(BasicAuthenticatorConstants.FAILED_USERNAME,
                                URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8));
                        if (StringUtils.isNotBlank(reason)) {
                            retryParam = BasicAuthenticatorConstants.AUTH_FAILURE_PARAM + "true" +
                                    BasicAuthenticatorConstants.AUTH_FAILURE_MSG_PARAM + URLEncoder.encode(reason,
                                    BasicAuthenticatorConstants.UTF_8);
                        }
                        retryParam = retryParam + buildErrorParamString(paramMap);
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

            redirectURL += getCaptchaParams(context.getTenantDomain());
            response.sendRedirect(redirectURL);
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.SYSTEM_ERROR_WHILE_AUTHENTICATING.getCode(),
                    e.getMessage(),
                    User.getUserFromUserName(request.getParameter(BasicAuthenticatorConstants.USER_NAME)), e);
        }
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        if (!IdentityUtil.isEmailUsernameValidationDisabled()) {
            FrameworkUtils.validateUsername(username, context);
            username = FrameworkUtils.preprocessUsername(username, context);
        }
        String requestTenantDomain = MultitenantUtils.getTenantDomain(username);
        ResolvedUserResult resolvedUserResult = FrameworkUtils.processMultiAttributeLoginIdentification(
                MultitenantUtils.getTenantAwareUsername(username), requestTenantDomain);
        if (resolvedUserResult != null && ResolvedUserResult.UserResolvedStatus.SUCCESS.
                equals(resolvedUserResult.getResolvedStatus())) {
            username = UserCoreUtil.addTenantDomainToEntry(resolvedUserResult.getUser().getUsername(),
                    requestTenantDomain);
        }
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (runtimeParams != null) {
            String usernameFromContext = runtimeParams.get(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME);
            if (usernameFromContext != null && !usernameFromContext.equals(username)) {
                if (log.isDebugEnabled()) {
                    log.debug("Username set for identifier first login: " + usernameFromContext + " and username " +
                            "submitted from login page" + username + " does not match.");
                }
                throw new InvalidCredentialsException(ErrorMessages.CREDENTIAL_MISMATCH.getCode(),
                        ErrorMessages.CREDENTIAL_MISMATCH.getMessage());
            }
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        boolean isAuthenticated;
        UserStoreManager userStoreManager = getUserStoreManager(username);
        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        try {
            setUserExistThreadLocal();
            isAuthenticated = userStoreManager.authenticate(
                    MultitenantUtils.getTenantAwareUsername(username), password);
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
            throw new AuthenticationFailedException(
                    ErrorMessages.USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE.getCode(), e.getMessage(),
                    User.getUserFromUserName(username), e);
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
            throw new InvalidCredentialsException(ErrorMessages.INVALID_CREDENTIALS.getCode(),
                    ErrorMessages.INVALID_CREDENTIALS.getMessage(), User.getUserFromUserName(username));
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        //TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", tenantDomain);

        username = getMultiAttributeUsername(FrameworkUtils.prependUserStoreDomainToName(username), tenantDomain,
                userStoreManager);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
        String rememberMe = request.getParameter("chkRemember");

        if ("on".equals(rememberMe)) {
            context.setRememberMe(true);
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

    private String buildErrorParamString(Map<String, String> paramMap) {

        StringBuilder params = new StringBuilder();
        for (Map.Entry<String, String> entry : paramMap.entrySet()) {
            params.append(filterAndAddParam(entry.getKey(), entry.getValue()));
        }
        return params.toString();
    }

    private String filterAndAddParam(String key, String value) {

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
     * @param tenantDomain tenant domain of the application
     * @return string with the appended recaptcha params
     */
    private String getCaptchaParams(String tenantDomain) {

        SSOLoginReCaptchaConfig connector = new SSOLoginReCaptchaConfig();
        String defaultCaptchaConfigName = connector.getName() +
                CaptchaConstants.ReCaptchaConnectorPropertySuffixes.ENABLE_ALWAYS;

        String captchaParams = "";
        Property[] connectorConfigs;
        Properties captchaConfigs = getCaptchaConfigs();

        if (captchaConfigs != null && !captchaConfigs.isEmpty() &&
                Boolean.parseBoolean(captchaConfigs.getProperty(CaptchaConstants.RE_CAPTCHA_PARAMETERS_IN_URL_ENABLED))) {

            if (Boolean.parseBoolean(captchaConfigs.getProperty(CaptchaConstants.RE_CAPTCHA_ENABLED))) {

                try {
                    connectorConfigs = BasicAuthenticatorDataHolder.getInstance().getIdentityGovernanceService()
                            .getConfiguration(new String[]{defaultCaptchaConfigName,
                                            RESEND_CONFIRMATION_RECAPTCHA_ENABLE}, tenantDomain);

                    for (Property connectorConfig : connectorConfigs) {
                        if (defaultCaptchaConfigName.equals(connectorConfig.getName())) {
                            // SSO Login Captcha Config
                            if (Boolean.parseBoolean(connectorConfig.getValue())) {
                                captchaParams = BasicAuthenticatorConstants.RECAPTCHA_PARAM + "true";
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("Enforcing recaptcha for SSO Login is not enabled.");
                                }
                            }
                        } else if ((RESEND_CONFIRMATION_RECAPTCHA_ENABLE).equals(connectorConfig.getName())) {
                            // Resend Confirmation Captcha Config
                            if (Boolean.parseBoolean(connectorConfig.getValue())) {
                                captchaParams += BasicAuthenticatorConstants.RECAPTCHA_RESEND_CONFIRMATION_PARAM +
                                        "true";
                            } else {
                                if (log.isDebugEnabled()) {
                                    log.debug("Enforcing recaptcha for resend confirmation is not enabled.");
                                }
                            }
                        }
                    }

                    // Add captcha configs
                    if (!captchaParams.isEmpty()) {
                        captchaParams += BasicAuthenticatorConstants.RECAPTCHA_KEY_PARAM + captchaConfigs.getProperty
                                (CaptchaConstants.RE_CAPTCHA_SITE_KEY) +
                                BasicAuthenticatorConstants.RECAPTCHA_API_PARAM + captchaConfigs.getProperty
                                (CaptchaConstants.RE_CAPTCHA_API_URL);
                    }

                } catch (IdentityGovernanceException e) {
                    log.error("Error occurred while verifying the captcha configs. Proceeding the authentication " +
                            "request without enabling recaptcha.", e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Recaptcha is not enabled.");
                }
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

    private void removeAutoLoginCookie(HttpServletResponse response, Cookie autoLoginCookie) {

        autoLoginCookie.setMaxAge(0);
        autoLoginCookie.setValue("");
        autoLoginCookie.setPath("/");
        response.addCookie(autoLoginCookie);
    }

    private void validateCookieSignature(String content, String signature, String alias)
            throws AuthenticationFailedException {


        if (StringUtils.isEmpty(content) || StringUtils.isEmpty(signature)) {
            throw new AuthenticationFailedException("Either 'content' or 'signature' attribute is missing in value of" +
                    " Auto Login Cookie.");
        }

        try {
            boolean isSignatureValid;
            if (StringUtils.isEmpty(alias)) {
                isSignatureValid = SignatureUtil.validateSignature(content, Base64.getDecoder().decode(signature));
            } else {
                byte[] thumpPrint = SignatureUtil.getThumbPrintForAlias(alias);
                isSignatureValid = SignatureUtil.validateSignature(thumpPrint, content,
                        Base64.getDecoder().decode(signature));
            }
            if (!isSignatureValid) {
                throw new AuthenticationFailedException("Signature verification failed in Auto Login Cookie " +
                        "for user: " + content);
            }
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while validating the signature for the Auto " +
                    "Login Cookie");
        }
    }

    private JSONObject transformToJSON(String value) throws AuthenticationFailedException {

        JSONParser jsonParser = new JSONParser();
        try {
            return (JSONObject) jsonParser.parse(value);
        } catch (ParseException e) {
            throw new AuthenticationFailedException("Error occurred while parsing the Auto Login Cookie JSON string " +
                    "to a JSON object", e);
        }
    }
    private boolean isEnableAutoLoginEnabled(AuthenticationContext context, Cookie autoLoginCookie)
            throws AuthenticationFailedException {

        String flowType = resolveAutoLoginFlow(autoLoginCookie.getValue());
        if (AutoLoginConstant.SIGNUP.equals(flowType)) {
            return isEnableSelfRegistrationAutoLogin(context);
        } else if (AutoLoginConstant.RECOVERY.equals(flowType)) {
            return isEnableAutoLoginAfterPasswordReset(context);
        }
        return false;
    }

    private String resolveAutoLoginFlow(String cookieValue) throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(cookieValue));
        JSONObject cookieValueJSON = transformToJSON(decodedValue);
        String usernameInCookie = (String) cookieValueJSON.get(AutoLoginConstant.USERNAME);
        if (StringUtils.isNotEmpty(usernameInCookie)) {
            if (log.isDebugEnabled()) {
                log.debug("Received ALOR cookie is an old format, so considering it as a recovery flow.");
            }
            return "RECOVERY";
        }
        return (String) transformToJSON((String)cookieValueJSON.get(AutoLoginConstant.CONTENT)).get(AutoLoginConstant.FLOW_TYPE);
    }

    public boolean isEnableSelfRegistrationAutoLogin(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(Utils.getConnectorConfig(AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN,
                    context.getTenantDomain()));
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving isEnableSelfRegistrationAutoLogin" +
                    " property.", e);
        }
    }

    public String getSelfRegistrationAutoLoginAlias(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            return Utils.getConnectorConfig(AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME,
                    context.getTenantDomain());
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving " +
                    AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME + " property.", e);
        }
    }

    private boolean isEnableAutoLoginAfterPasswordReset(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    Utils.getConnectorConfig(AutoLoginConstant.RECOVERY_ADMIN_PASSWORD_RESET_AUTO_LOGIN,
                            context.getTenantDomain()));
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving isEnableAutoLogin property.", e);
        }
    }

    private String getMultiAttributeUsername(String username, String tenantDomain, UserStoreManager userStoreManager) {

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String userNameUri = getAuthenticatorConfig().getParameterMap().get("UserNameAttributeClaimUri");
            if (StringUtils.isNotBlank(userNameUri)) {
                boolean multipleAttributeEnable;
                String domain = UserCoreUtil.getDomainFromThreadLocal();
                if (StringUtils.isNotBlank(domain)) {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.getSecondaryUserStoreManager(domain)
                            .getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                } else {
                    multipleAttributeEnable = Boolean.parseBoolean(userStoreManager.
                            getRealmConfiguration().getUserStoreProperty("MultipleAttributeEnable"));
                }
                if (multipleAttributeEnable) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Searching for UserNameAttribute value for user " + username +
                                    " for claim uri : " + userNameUri);
                        }
                        String usernameValue = userStoreManager.
                                getUserClaimValue(MultitenantUtils.getTenantAwareUsername(username), userNameUri, null);
                        if (StringUtils.isNotBlank(usernameValue)) {
                            usernameValue = FrameworkUtils.prependUserStoreDomainToName(usernameValue);
                            username = usernameValue + "@" + tenantDomain;
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user. Value is :  " + username);
                            }
                        }
                    } catch (UserStoreException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Error while retrieving UserNameAttribute for user : " + username, e);
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
        return username;
    }

    private UserStoreManager getUserStoreManager(String username) throws AuthenticationFailedException {

        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                return (UserStoreManager) userRealm.getUserStoreManager();
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Can't find the UserStoreManager the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    private Cookie getAutoLoginCookie(Cookie[] cookiesInRequest) {

        Optional<Cookie> targetCookie = Optional.empty();
        if (ArrayUtils.isNotEmpty(cookiesInRequest)) {
            targetCookie = Arrays.stream(cookiesInRequest)
                    .filter(cookie -> StringUtils.equalsIgnoreCase(AutoLoginConstant.COOKIE_NAME, cookie.getName()))
                    .filter(cookie -> StringUtils.isNotEmpty(cookie.getValue()))
                    .findFirst();
        }

        return targetCookie.orElse(null);
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
}
