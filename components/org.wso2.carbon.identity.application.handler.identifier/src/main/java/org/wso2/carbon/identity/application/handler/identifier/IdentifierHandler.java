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

package org.wso2.carbon.identity.application.handler.identifier;

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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.handler.identifier.internal.IdentifierAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Identifier based handler.
 */
public class IdentifierHandler extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final long serialVersionUID = 1819664539416029785L;
    private static final Log log = LogFactory.getLog(IdentifierHandler.class);
    private static String RE_CAPTCHA_USER_DOMAIN = "user-domain-recaptcha";

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(IdentifierHandlerConstants.USER_NAME);
        return userName != null;
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

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=username.fail.message";
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

                } else if (showAuthFailureReason != null && "true".equals(showAuthFailureReason)) {

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
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam);
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
                        }
                        response.sendRedirect(redirectURL);

                    } else if (errorCode.equals(UserCoreConstants.ErrorCode.USER_DOES_NOT_EXIST)) {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam);
                    } else if (errorCode.equals(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE)) {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                                IdentifierHandlerConstants.LOCAL + retryParam);
                    } else {
                        retryParam = retryParam + IdentifierHandlerConstants.ERROR_CODE + errorCode
                                + IdentifierHandlerConstants.FAILED_USERNAME + URLEncoder
                                .encode(request.getParameter(IdentifierHandlerConstants.USER_NAME),
                                        IdentifierHandlerConstants.UTF_8);
                        response.sendRedirect(loginPage + ("?" + queryParams)
                                + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":"
                                + IdentifierHandlerConstants.LOCAL + retryParam);
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Unknown identity error code.");
                    }
                    response.sendRedirect(loginPage + ("?" + queryParams)
                            + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                            IdentifierHandlerConstants.LOCAL + retryParam);

                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Identity error message context is null");
                }
                response.sendRedirect(loginPage + ("?" + queryParams)
                        + IdentifierHandlerConstants.AUTHENTICATORS + getName() + ":" +
                        IdentifierHandlerConstants.LOCAL + retryParam);
            }


        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(request.getParameter
                    (IdentifierHandlerConstants.USER_NAME)), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = request.getParameter(IdentifierHandlerConstants.USER_NAME);

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String validateUsername = getAuthenticatorConfig().getParameterMap().get("ValidateUsername");
            if (Boolean.valueOf(validateUsername)) {
                boolean isUserExists;
                UserStoreManager userStoreManager;
                // Check for the username exists.
                try {
                    int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                    UserRealm userRealm = IdentifierAuthenticatorServiceComponent.getRealmService()
                            .getTenantUserRealm(tenantId);

                    if (userRealm != null) {
                        userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                        isUserExists = userStoreManager.isExistingUser(MultitenantUtils.getTenantAwareUsername
                                (username));
                    } else {
                        throw new AuthenticationFailedException("Cannot find the user realm for the given tenant: " +
                                tenantId, User.getUserFromUserName(username));
                    }
                } catch (IdentityRuntimeException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("IdentifierHandler failed while trying to get the tenant ID of the user " +
                                username, e);
                    }
                    throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
                } catch (org.wso2.carbon.user.api.UserStoreException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("IdentifierHandler failed while trying to authenticate", e);
                    }
                    throw new AuthenticationFailedException(e.getMessage(), User.getUserFromUserName(username), e);
                }

                if (!isUserExists) {
                    if (log.isDebugEnabled()) {
                        log.debug("User does not exists");
                    }
                    if (IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN) != null) {
                        username = IdentityUtil.addDomainToName(
                                username, IdentityUtil.threadLocalProperties.get().get(RE_CAPTCHA_USER_DOMAIN)
                                        .toString());
                    }
                    IdentityUtil.threadLocalProperties.get().remove(RE_CAPTCHA_USER_DOMAIN);
                    throw new InvalidCredentialsException("User  does not exists", User.getUserFromUserName(username));
                }

                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                //TODO: user tenant domain has to be an attribute in the AuthenticationContext
                authProperties.put("user-tenant-domain", tenantDomain);
            }
        }

        username = FrameworkUtils.prependUserStoreDomainToName(username);
        authProperties.put("username", username);

        Map<String, String> identifierParams = new HashMap<>();
        identifierParams.put(FrameworkConstants.JSAttributes.JS_OPTIONS_USERNAME, username);
        Map<String, Map<String, String>> contextParams =  new HashMap<>();
        contextParams.put(FrameworkConstants.JSAttributes.JS_COMMON_OPTIONS, identifierParams);
        context.addAuthenticatorParams(contextParams);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
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
        return IdentifierHandlerConstants.HANDLER_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return IdentifierHandlerConstants.HANDLER_NAME;
    }
}
