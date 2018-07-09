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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.application.authenticator.basicauth.internal.BasicAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Username Password based Authenticator
 */
public class BasicAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 1819664539416029785L;
    private static final String PASSWORD_PROPERTY = "PASSWORD_PROPERTY";
    private static final String PASSWORD_RESET_ENDPOINT = "accountrecoveryendpoint/confirmrecovery.do?";
    private static final Log log = LogFactory.getLog(BasicAuthenticator.class);
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);
        return userName != null && password != null;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request,
                                           HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

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
        String password = (String) context.getProperty(PASSWORD_PROPERTY);
        context.getProperties().remove(PASSWORD_PROPERTY);

        Map<String, String> runtimeParams = context.getAuthenticatorParams(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS);
        String inputType = null;
        if (runtimeParams != null) {
            String usernameFromContext = runtimeParams.get("username");
            String inputTypeFromContext = runtimeParams.get("inputType");
            if ("identifierFirst".equalsIgnoreCase(inputTypeFromContext)) {
                inputType = FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST;
            }
            if (FrameworkConstants.INPUT_TYPE_IDENTIFIER_FIRST.equalsIgnoreCase(inputType)) {
                queryParams += "&" + FrameworkConstants.RequestParams.INPUT_TYPE +"=" + inputType;
                //TODO remove this from url and add to the new endpoint.
                queryParams += "&username=" + usernameFromContext;
            }
        }

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
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
                String errorCode = errorContext.getErrorCode();

                if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_NOT_CONFIRMED_ERROR_CODE)) {
                    retryParam = "&authFailure=true&authFailureMsg=account.confirmation.pending";
                    String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
                    Object domain = IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN);
                    if (domain != null) {
                        username = IdentityUtil.addDomainToName(username, domain.toString());
                    }

                    String redirectURL = loginPage + ("?" + queryParams) + BasicAuthenticatorConstants.FAILED_USERNAME
                            + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants
                            .AUTHENTICATORS + getName() + ":" + BasicAuthenticatorConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);

                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_EMAIL_LINK_ERROR_CODE)) {
                    retryParam = "&authFailure=true&authFailureMsg=password.reset.pending";
                    String redirectURL = loginPage + ("?" + queryParams) +
                            BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(request.getParameter(
                            BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.ERROR_CODE + errorCode +
                            BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL + retryParam;
                    response.sendRedirect(redirectURL);

                } else if (errorCode.equals(
                        IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_ERROR_CODE)) {
                    String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
                    String tenantDoamin = MultitenantUtils.getTenantDomain(username);
                    String redirectURL = (PASSWORD_RESET_ENDPOINT + queryParams) +
                            BasicAuthenticatorConstants.USER_NAME_PARAM + URLEncoder.encode(username, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.TENANT_DOMAIN_PARAM + URLEncoder.encode(tenantDoamin, BasicAuthenticatorConstants.UTF_8) +
                            BasicAuthenticatorConstants.CONFIRMATION_PARAM + URLEncoder.encode(password, BasicAuthenticatorConstants.UTF_8);
                    response.sendRedirect(redirectURL);

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
                        log.debug("username : " + request.getParameter(BasicAuthenticatorConstants.USER_NAME));
                        log.debug("remainingAttempts : " + remainingAttempts);
                    }

                    if (errorCode.equals(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL)) {
                        retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8)
                                + "&remainingAttempts=" + remainingAttempts;
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_IS_LOCKED)) {
                        String redirectURL = retryPage;
                        if (remainingAttempts == 0) {
                            if (StringUtils.isBlank(reason)) {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8) +
                                        "&remainingAttempts=0";
                            } else {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode + "&lockedReason="
                                        + reason + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                                BasicAuthenticatorConstants.UTF_8) + "&remainingAttempts=0";
                            }
                        } else {
                            if (StringUtils.isBlank(reason)) {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8);
                            } else {
                                redirectURL = response.encodeRedirectURL(redirectURL + ("?" + queryParams)) +
                                        BasicAuthenticatorConstants.ERROR_CODE + errorCode + "&lockedReason="
                                        + reason + BasicAuthenticatorConstants.FAILED_USERNAME +
                                        URLEncoder.encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                                BasicAuthenticatorConstants.UTF_8);
                            }
                        }
                        response.sendRedirect(redirectURL);

                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                        retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
                        retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(
                            IdentityCoreConstants.ADMIN_FORCED_USER_PASSWORD_RESET_VIA_OTP_MISMATCHED_ERROR_CODE)) {
                        retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
                        String redirectURL = loginPage + ("?" + queryParams) +
                                BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder.encode(request.getParameter(
                                BasicAuthenticatorConstants.USER_NAME), BasicAuthenticatorConstants.UTF_8) +
                                BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                                BasicAuthenticatorConstants.LOCAL + retryParam;
                        response.sendRedirect(redirectURL);
                    } else {
                        retryParam = retryParam + BasicAuthenticatorConstants.ERROR_CODE + errorCode
                                + BasicAuthenticatorConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(BasicAuthenticatorConstants.USER_NAME),
                                        BasicAuthenticatorConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":"
                                + BasicAuthenticatorConstants.LOCAL + retryParam);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                    response.sendRedirect(loginPage + ("?" + queryParams)
                            + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                            BasicAuthenticatorConstants.LOCAL + retryParam);

                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                response.sendRedirect(loginPage + ("?" + queryParams)
                        + BasicAuthenticatorConstants.AUTHENTICATORS + getName() + ":" +
                        BasicAuthenticatorConstants.LOCAL + retryParam);
            }


        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                    (BasicAuthenticatorConstants.USER_NAME)), e);
        }
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(BasicAuthenticatorConstants.USER_NAME);
        String password = request.getParameter(BasicAuthenticatorConstants.PASSWORD);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        authProperties.put(PASSWORD_PROPERTY, password);

        boolean isAuthenticated;
        UserStoreManager userStoreManager;
        // Reset RE_CAPTCHA_USER_DOMAIN thread local variable before the authentication
        IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
        // Check the authentication
        try {
            int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            UserRealm userRealm = BasicAuthenticatorServiceComponent.getRealmService().getTenantUserRealm(tenantId);
            if (userRealm != null) {
                userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                isAuthenticated = userStoreManager.authenticate(
                        MultitenantUtils.getTenantAwareUsername(username), password);
            } else {
                throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                        tenantId, User.getUserFromUserName(username));
            }
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to get the tenant ID of the user " + username, e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("BasicAuthentication failed while trying to authenticate", e);
            }
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
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
            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }


        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        //TODO: user tenant domain has to be an attribute in the AuthenticationContext
        authProperties.put("user-tenant-domain", tenantDomain);

        username = FrameworkUtils.prependUserStoreDomainToName(username);

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
                            tenantDomain = MultitenantUtils.getTenantDomain(username);
                            usernameValue = FrameworkUtils.prependUserStoreDomainToName(usernameValue);
                            username = usernameValue + "@" + tenantDomain;
                            if (log.isDebugEnabled()) {
                                log.debug("UserNameAttribute is found for user. Value is :  " + username);
                            }
                        }
                    } catch (UserStoreException e) {
                        //ignore  but log in debug
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
}
