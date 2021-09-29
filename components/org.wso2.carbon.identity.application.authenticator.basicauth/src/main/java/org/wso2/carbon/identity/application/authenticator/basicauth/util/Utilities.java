/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org).
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

package org.wso2.carbon.identity.application.authenticator.basicauth.util;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.core.util.SignatureUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.recovery.util.Utils;

import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * Utilities class for basic authenticator.
 */
public class Utilities {

    /**
     * Get ALOR cookie from provided list of cookies.
     *
     * @param cookiesInRequest List of cookies in the request.
     * @return ALOR cookie if present, else null.
     */
    public static Cookie getAutoLoginCookie(Cookie[] cookiesInRequest) {

        Optional<Cookie> targetCookie = Optional.empty();
        if (ArrayUtils.isNotEmpty(cookiesInRequest)) {
            targetCookie = Arrays.stream(cookiesInRequest)
                    .filter(cookie -> StringUtils.equalsIgnoreCase(AutoLoginConstant.COOKIE_NAME,
                            cookie.getName()))
                    .filter(cookie -> StringUtils.isNotEmpty(cookie.getValue()))
                    .findFirst();
        }
        return targetCookie.orElse(null);
    }

    /**
     * Check if auto login is enabled.
     *
     * @param context         Authentication context.
     * @param autoLoginCookie Auto login cookie.
     * @return true if auto login is enabled.
     * @throws AuthenticationFailedException
     */
    public static boolean isEnableAutoLoginEnabled(AuthenticationContext context, Cookie autoLoginCookie)
            throws AuthenticationFailedException {

        String flowType = resolveAutoLoginFlow(autoLoginCookie.getValue());
        if (AutoLoginConstant.SIGNUP.equals(flowType)) {
            return isEnableSelfRegistrationAutoLogin(context);
        } else if (AutoLoginConstant.RECOVERY.equals(flowType)) {
            return isEnableAutoLoginAfterPasswordReset(context);
        }
        return false;
    }

    /**
     * Check if auto login is enabled for password reset.
     *
     * @param context Authentication context.
     * @return true if enabled.
     * @throws AuthenticationFailedException
     */
    public static boolean isEnableAutoLoginAfterPasswordReset(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    Utils.getConnectorConfig(
                            AutoLoginConstant.RECOVERY_ADMIN_PASSWORD_RESET_AUTO_LOGIN,
                            context.getTenantDomain()));
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving isEnableAutoLogin property.", e);
        }
    }

    /**
     * Check if auto login is enabled for self registration.
     *
     * @param context Authentication context.
     * @return true if enabled.
     * @throws AuthenticationFailedException
     */
    public static boolean isEnableSelfRegistrationAutoLogin(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    Utils.getConnectorConfig(AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN,
                            context.getTenantDomain()));
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving isEnableSelfRegistrationAutoLogin" +
                    " property.", e);
        }
    }

    /**
     * Transform a given JSON string to a JSONObject.
     *
     * @param value JSON string.
     * @return JSON object.
     * @throws AuthenticationFailedException
     */
    public static JSONObject transformToJSON(String value) throws AuthenticationFailedException {

        JSONParser jsonParser = new JSONParser();
        try {
            return (org.json.simple.JSONObject) jsonParser.parse(value);
        } catch (ParseException e) {
            throw new AuthenticationFailedException("Error occurred while parsing the Auto Login Cookie JSON string " +
                    "to a JSON object", e);
        }
    }

    /**
     * Remove auto login cookie from the authentication response.
     *
     * @param response        Authentication response.
     * @param autoLoginCookie Auto login cookie.
     * @throws AuthenticationFailedException
     */
    public static void removeAutoLoginCookieInResponse(HttpServletResponse response, Cookie autoLoginCookie)
            throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(autoLoginCookie.getValue()));
        JSONObject cookieValueJSON = transformToJSON(decodedValue);
        String content = (String) cookieValueJSON.get(AutoLoginConstant.CONTENT);
        JSONObject contentJSON = transformToJSON(content);
        String domainInCookie = (String) contentJSON.get(AutoLoginConstant.DOMAIN);
        if (StringUtils.isNotEmpty(domainInCookie)) {
            autoLoginCookie.setDomain(domainInCookie);
        }
        autoLoginCookie.setMaxAge(0);
        autoLoginCookie.setValue("");
        autoLoginCookie.setPath("/");
        response.addCookie(autoLoginCookie);
    }

    /**
     * Get certificate alias related self registration auto login.
     *
     * @param context Authentication context.
     * @return Certificate alias.
     * @throws AuthenticationFailedException
     */
    public static String getSelfRegistrationAutoLoginAlias(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return Utils.getConnectorConfig(
                    AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME,
                    context.getTenantDomain());
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while resolving " +
                    AutoLoginConstant.SELF_REGISTRATION_AUTO_LOGIN_ALIAS_NAME + " property.", e);
        }
    }

    /**
     * @param context
     * @param authenticatorConfig
     * @param content
     * @param signature
     * @throws AuthenticationFailedException
     */
    public static void validateAutoLoginCookie(AuthenticationContext context, AuthenticatorConfig authenticatorConfig,
                                               String content, String signature) throws AuthenticationFailedException {

        JSONObject contentJSON = Utilities.transformToJSON(content);
        // Cookie expiry validation.
        if (contentJSON.get(AutoLoginConstant.CREATED_TIME) == null) {
            throw new AuthenticationFailedException("The created time is not available in the ALOR cookie content.");
        }
        long createdTime = (long) contentJSON.get(AutoLoginConstant.CREATED_TIME);
        validateAutoLoginCookieCreatedTime(createdTime, authenticatorConfig);
        // Signature validation.
        String alias = null;
        String flowType = (String) contentJSON.get(AutoLoginConstant.FLOW_TYPE);
        if (AutoLoginConstant.SIGNUP.equals(flowType)) {
            alias = getSelfRegistrationAutoLoginAlias(context);
        }
        validateAutoLoginCookieSignature(content, signature, alias);
    }

    private static void validateAutoLoginCookieSignature(String content, String signature, String alias)
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

    private static void validateAutoLoginCookieCreatedTime(long createdTime, AuthenticatorConfig authenticatorConfig)
            throws AuthenticationFailedException {

        String cookieMaxAge = AutoLoginConstant.DEFAULT_COOKIE_MAX_AGE;
        if (authenticatorConfig.getParameterMap() != null) {
            String autoLoginCookieMaxAge = authenticatorConfig.getParameterMap().get("AutoLoginCookieMaxAge");
            if (StringUtils.isNotEmpty(autoLoginCookieMaxAge)) {
                cookieMaxAge = autoLoginCookieMaxAge;
            }
        }
        long maxAgeTime = TimeUnit.SECONDS.toMillis(Long.parseLong(cookieMaxAge));
        long currentTime = System.currentTimeMillis();
        if (currentTime - createdTime > maxAgeTime) {
            throw new AuthenticationFailedException("The Auto Login Cookie expired.");
        }
    }

    private static String resolveAutoLoginFlow(String cookieValue) throws AuthenticationFailedException {

        String decodedValue = new String(Base64.getDecoder().decode(cookieValue));
        JSONObject cookieValueJSON = transformToJSON(decodedValue);
        JSONObject content =
                transformToJSON((String) cookieValueJSON.get(AutoLoginConstant.CONTENT));
        return (String) content.get(AutoLoginConstant.FLOW_TYPE);
    }
}
