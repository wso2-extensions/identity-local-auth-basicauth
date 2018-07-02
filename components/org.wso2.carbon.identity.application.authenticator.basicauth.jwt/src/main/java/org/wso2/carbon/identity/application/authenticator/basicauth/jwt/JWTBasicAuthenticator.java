/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.jwt.cache.AuthJwtCache;
import org.wso2.carbon.identity.application.authenticator.basicauth.jwt.internal
        .JWTBasicAuthenticatorServiceComponentDataHolder;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.security.KeyStore;
import java.security.KeyStoreException;
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

    private static long DEFAULT_TIMESTAMP_SKEW = 300;

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
                if (rememberMe != null && "on".equals(rememberMe)) {
                    context.setRememberMe(true);
                }
            } else {
                throw new AuthenticationFailedException("User authentication failed : Invalid signature.");
            }
        } else {
            throw new AuthenticationFailedException("Invalid token");
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
        SignedJWT signedJWT;
        if (StringUtils.isBlank(jwtAssertion)) {
            throw new AuthenticationFailedException(errorMessage);
        }

        try {
            signedJWT = SignedJWT.parse(jwtAssertion);
        } catch (ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
            throw new AuthenticationFailedException("Error while parsing the JWT.");
        }

        if (signedJWT == null) {
            throw new AuthenticationFailedException(errorMessage);
        }
        return signedJWT;
    }

    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws AuthenticationFailedException {

        if (signedJWT == null) {
            throw new AuthenticationFailedException("No Valid JWT Assertion was found.");
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();

            if (claimsSet == null) {
                throw new AuthenticationFailedException("Claim values are empty in the given JWT.");
            }
        } catch (ParseException e) {
            String errorMsg = "Error when trying to retrieve claimsSet from the JWT.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new AuthenticationFailedException(errorMsg);
        }
        return claimsSet;
    }

    private boolean isValidClaimSet(JWTClaimsSet claimsSet) throws AuthenticationFailedException {

        if (StringUtils.isEmpty(claimsSet.getSubject()) || StringUtils.isEmpty(claimsSet.getIssuer()) || StringUtils
                .isEmpty(claimsSet.getJWTID()) || claimsSet.getExpirationTime() == null) {
            throw new AuthenticationFailedException("Invalid token : Required fields are not present in JWT.");
        }

        if (AuthJwtCache.getInstance().getValueFromCache(claimsSet.getJWTID()) != null) {
            throw new AuthenticationFailedException("Invalid token : Possible replay attack.");
        }

        return checkExpirationTime(claimsSet.getExpirationTime().getTime(), System.currentTimeMillis(),
                getTimeStampSkew());
    }

    private boolean isValidSignature(SignedJWT signedJWT, String tenantDomain) throws AuthenticationFailedException {

        X509Certificate cert = getCertificate(tenantDomain);
        return validateSignature(signedJWT, cert);
    }

    private X509Certificate getCertificate(String tenantDomain) throws AuthenticationFailedException {

        int tenantId;
        try {
            tenantId = JWTBasicAuthenticatorServiceComponentDataHolder.getInstance().getRealmService()
                    .getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error while getting the tenant ID from the tenant domain : " + tenantDomain;
            throw new AuthenticationFailedException(errorMsg);
        }

        // get an instance of the corresponding Key Store Manager instance
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        try {
            if (tenantId != MultitenantConstants.SUPER_TENANT_ID) {
                // for tenants, load key from their generated key store and get the primary certificate.
                KeyStore keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                return (X509Certificate) keyStore.getCertificate(tenantDomain);
            } else {
                // for super tenant, load the default public cert using the config in carbon.xml
                return keyStoreManager.getDefaultPrimaryCertificate();
            }
        } catch (KeyStoreException e) {
            String errorMsg = "Error instantiating an X509Certificate object for the primary certificate  in tenant: " +
                    "" + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new AuthenticationFailedException(errorMsg);
        } catch (Exception e) {
            String errorMsg = "Unable to load key store manager for the tenant domain: " + tenantDomain;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new AuthenticationFailedException(errorMsg);
        }
    }

    private String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(JWTBasicAuthenticatorConstants.FULLSTOP_DELIMITER,
                JWTBasicAuthenticatorConstants.DASH_DELIMITER);
        return ksName + JWTBasicAuthenticatorConstants.KEYSTORE_FILE_EXTENSION;
    }

    private boolean validateSignature(SignedJWT signedJWT, X509Certificate x509Certificate) throws
            AuthenticationFailedException {

        JWSHeader header = signedJWT.getHeader();
        if (x509Certificate == null) {
            throw new AuthenticationFailedException("Unable to locate certificate for JWT " + header.toString());
        }

        JWSVerifier verifier;
        String alg = header.getAlgorithm().getName();
        if (StringUtils.isEmpty(alg)) {
            throw new AuthenticationFailedException("Signature validation failed. No algorithm is found in JWT " +
                    "header.");
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
                    throw new AuthenticationFailedException("Signature validation failed. Public key is not an RSA "
                            + "public key.");
                }
            } else {
                throw new AuthenticationFailedException("Signature Algorithm not supported : " + alg);
            }
        }

        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            String errorMsg = "Signature verification failed for the JWT.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new AuthenticationFailedException(errorMsg);
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

            throw new AuthenticationFailedException("Invalid token : Token is expired.");
        }
        return true;
    }

}


