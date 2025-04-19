/*
 * Copyright (c) 2018-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.basicauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.jwt.cache.AuthJwtCache;
import org.wso2.carbon.identity.application.authenticator.basicauth.jwt.util.JwtBasicAuthErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Signed JWT token based Authenticator
 */
public class JWTBasicAuthenticator extends BasicAuthenticator {

    private static final Log log = LogFactory.getLog(JWTBasicAuthenticator.class);

    private static final long DEFAULT_TIMESTAMP_SKEW = 300;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String token = request.getParameter(JWTBasicAuthenticatorConstants.PARAM_TOKEN);
        return token != null;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String authToken = request.getParameter(JWTBasicAuthenticatorConstants.PARAM_TOKEN);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(JWTBasicAuthenticatorConstants.AUTH_TOKEN)) {
            log.debug("User authentication token : " + authToken);
        }

        Map<String, Object> authProperties = context.getProperties();
        if (authProperties == null) {
            authProperties = new HashMap<>();
            context.setProperties(authProperties);
        }

        SignedJWT signedJWT = getSignedJWT(authToken);
        JWTClaimsSet claimsSet = getClaimSet(signedJWT);

        if (isValidClaimSet(claimsSet)) {
            String username = claimsSet.getSubject();
            User user = User.getUserFromUserName(username);
            if (isValidSignature(signedJWT, user.getTenantDomain())) {
                AuthJwtCache.getInstance().addToCache(claimsSet.getJWTID(), claimsSet.getJWTID());
                authProperties.put("user-tenant-domain", user.getTenantDomain());
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
                String rememberMe = request.getParameter("chkRemember");
                if ("on".equals(rememberMe)) {
                    context.setRememberMe(true);
                }
            } else {
                throw new AuthenticationFailedException(ErrorMessages.INVALID_SIGNATURE.getCode(),
                        ErrorMessages.INVALID_SIGNATURE.getMessage());
            }
        } else {
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TOKEN.getCode(),
                    ErrorMessages.INVALID_TOKEN.getMessage());
        }
    }

    @Override
    public String getFriendlyName() {
        return JWTBasicAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return JWTBasicAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    private SignedJWT getSignedJWT(String jwtAssertion) throws AuthenticationFailedException {

        String errorMessage = "No Valid JWT Assertion was found.";
        if (StringUtils.isBlank(jwtAssertion)) {
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TOKEN.getCode(), errorMessage);
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtAssertion);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TOKEN.getCode(),
                    "Error while parsing the JWT.");
        }

        return signedJWT;
    }

    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws AuthenticationFailedException {

        if (signedJWT == null) {
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TOKEN.getCode(),
                    "No Valid JWT Assertion was found.");
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet == null) {
                throw new AuthenticationFailedException("Claim values are empty in the given JWT.");
            }
        } catch (ParseException e) {
            String errorMsg = ErrorMessages.RETRIEVING_CLAIMS_SET_FROM_JWT_FAILED.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(ErrorMessages.RETRIEVING_CLAIMS_SET_FROM_JWT_FAILED.getCode(),
                    errorMsg);
        }
        return claimsSet;
    }

    private boolean isValidClaimSet(JWTClaimsSet claimsSet) throws AuthenticationFailedException {

        if (StringUtils.isEmpty(claimsSet.getSubject()) || StringUtils.isEmpty(claimsSet.getIssuer()) || StringUtils
                .isEmpty(claimsSet.getJWTID()) || claimsSet.getExpirationTime() == null) {
            throw new AuthenticationFailedException(ErrorMessages.MISSING_REQUIRED_FIELDS_IN_JWT.getCode(),
                    ErrorMessages.MISSING_REQUIRED_FIELDS_IN_JWT.getMessage());
        }

        if (AuthJwtCache.getInstance().getValueFromCache(claimsSet.getJWTID()) != null) {
            throw new AuthenticationFailedException(ErrorMessages.INVALID_TOKEN_POSSIBLE_REPLAY_ATTACK.getCode(),
                    ErrorMessages.INVALID_TOKEN_POSSIBLE_REPLAY_ATTACK.getMessage());
        }

        return checkExpirationTime(claimsSet.getExpirationTime().getTime(), System.currentTimeMillis(),
                getTimeStampSkew());
    }

    private boolean isValidSignature(SignedJWT signedJWT, String tenantDomain) throws AuthenticationFailedException {

        X509Certificate cert = getCertificate(tenantDomain);
        return validateSignature(signedJWT, cert);
    }

    private X509Certificate getCertificate(String tenantDomain) throws AuthenticationFailedException {

        try {
            return (X509Certificate) IdentityKeyStoreResolver.getInstance().getCertificate(tenantDomain,
                    IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
        } catch (IdentityKeyStoreResolverException e) {
            String errorMsg = String.format(
                    "Error instantiating an X509Certificate object for the primary certificate in tenant: %s",
                    tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new AuthenticationFailedException(
                    ErrorMessages.KEY_STORE_EXCEPTION_WHILE_INSTANTIATING_X_509_CERTIFICATE_OBJECT.getCode(), errorMsg);
        }
    }

    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate) throws
            AuthenticationFailedException {

        JWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            throw new AuthenticationFailedException(ErrorMessages.UNABLE_TO_LOCATE_CERTIFICATE_FOR_JWT.getCode(),
                    String.format(ErrorMessages.UNABLE_TO_LOCATE_CERTIFICATE_FOR_JWT.getMessage(), header.toString()));
        }

        JWSVerifier verifier;
        String alg = header.getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new AuthenticationFailedException(
                    ErrorMessages.SIGNATURE_VALIDATION_ALGORITHM_NOT_FOUND_IN_JWT_HEADER.getCode(),
                    ErrorMessages.SIGNATURE_VALIDATION_ALGORITHM_NOT_FOUND_IN_JWT_HEADER.getMessage());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Signature Algorithm: " + alg + " found in JWT Header.");
            }
            // Only RSA Public Key is accepted.
            if (alg.indexOf("RS") == 0) {
                PublicKey publicKey = x509Certificate.getPublicKey();
                if (publicKey instanceof RSAPublicKey) {
                    verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
                } else {
                    throw new AuthenticationFailedException(
                            ErrorMessages.SIGNATURE_VALIDATION_PUBLIC_KEY_NOT_AN_RSA_PUBLIC_KEY.getCode(),
                            ErrorMessages.SIGNATURE_VALIDATION_PUBLIC_KEY_NOT_AN_RSA_PUBLIC_KEY.getMessage());
                }
            } else {
                throw new AuthenticationFailedException(ErrorMessages.SIGNATURE_ALGORITHM_NOT_SUPPORTED.getCode(),
                        String.format(ErrorMessages.SIGNATURE_ALGORITHM_NOT_SUPPORTED.getMessage(), alg));
            }
        }

        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            String errorMsg = ErrorMessages.SIGNATURE_VERIFICATION_FAILED_FOR_JWT.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new AuthenticationFailedException(ErrorMessages.SIGNATURE_VERIFICATION_FAILED_FOR_JWT.getCode(),
                    errorMsg);
        }
    }

    private long getTimeStampSkew() {

        if (getAuthenticatorConfig().getParameterMap() != null) {
            String timeStampSkewValue = getAuthenticatorConfig().getParameterMap().get(JWTBasicAuthenticatorConstants
                    .TIMESTAMP_SKEW);
            if (StringUtils.isNotBlank(timeStampSkewValue)) {
                try {
                    return Long.parseLong(timeStampSkewValue);
                } catch (NumberFormatException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse configured 'TimestampSkew' value: " + timeStampSkewValue + " to a " +
                                "" +  "long value. Picking the default value: " + DEFAULT_TIMESTAMP_SKEW);
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("'TimestampSkew' is not configured in application-authentication.xml file for the " +
                            "authenticator. Picking the default value: " + DEFAULT_TIMESTAMP_SKEW);
                }
            }
        }

        return DEFAULT_TIMESTAMP_SKEW;
    }

    private boolean checkExpirationTime(long expirationTimeInMillis, long currentTimeInMillis, long
            timeStampSkewMillis) throws AuthenticationFailedException {

        if ((currentTimeInMillis + timeStampSkewMillis) > expirationTimeInMillis) {
            if (log.isDebugEnabled()) {
                log.debug("JSON Web Token is expired." + ", Expiration Time(ms) : " + expirationTimeInMillis + ", " +
                        "TimeStamp Skew(ms) : " + timeStampSkewMillis + ", Current Time(ms) : " + currentTimeInMillis
                        + ". JWT Rejected and validation terminated");
            }
            throw new AuthenticationFailedException(ErrorMessages.TOKEN_EXPIRED.getCode(),
                    ErrorMessages.TOKEN_EXPIRED.getMessage());
        }
        return true;
    }

}


