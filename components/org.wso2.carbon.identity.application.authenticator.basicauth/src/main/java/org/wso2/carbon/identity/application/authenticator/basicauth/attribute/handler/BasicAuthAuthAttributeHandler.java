/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.basicauth.attribute.handler;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandler;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerBindingType;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttribute;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttributeHolder;
import org.wso2.carbon.identity.auth.attribute.handler.model.AuthAttributeType;
import org.wso2.carbon.identity.auth.attribute.handler.model.ValidationFailureReason;
import org.wso2.carbon.identity.auth.attribute.handler.model.ValidationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_NOT_FOUND;
import static org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandlerConstants.ErrorMessages.ERROR_CODE_ATTRIBUTE_VALUE_EMPTY;

/**
 * Auth attribute handler implementation for the BasicAuth authenticator.
 */
public class BasicAuthAuthAttributeHandler implements AuthAttributeHandler {

    private static final String HANDLER_NAME = "BasicAuthAuthAttributeHandler";
    private static final String ATTRIBUTE_USERNAME = "username";
    private static final String ATTRIBUTE_PASSWORD = "password";

    @Override
    public String getName() {

        return HANDLER_NAME;
    }

    @Override
    public AuthAttributeHandlerBindingType getBindingType() {

        return AuthAttributeHandlerBindingType.AUTHENTICATOR;
    }

    @Override
    public String getBoundIdentifier() {

        return BasicAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public AuthAttributeHolder getAuthAttributeData() {

        List<AuthAttribute> authAttributes = new ArrayList<>();
        authAttributes.add(buildAuthAttribute(ATTRIBUTE_USERNAME, false));
        authAttributes.add(buildAuthAttribute(ATTRIBUTE_PASSWORD, true));

        return new AuthAttributeHolder(
                getName(),
                getBindingType(),
                getBoundIdentifier(),
                authAttributes
        );
    }

    @Override
    public ValidationResult validateAttributes(Map<String, String> attributeMap) {

        ValidationResult validationResult = new ValidationResult(true);

        validateAttributeExistence(ATTRIBUTE_USERNAME, attributeMap, validationResult);
        validateAttributeExistence(ATTRIBUTE_PASSWORD, attributeMap, validationResult);

        return validationResult;
    }

    private AuthAttribute buildAuthAttribute(String name, boolean isConfidential) {

        return new AuthAttribute(name, false, isConfidential, AuthAttributeType.STRING);
    }

    private void validateAttributeExistence(String attribute, Map<String, String> attributeMap,
                                            ValidationResult validationResult) {

        if (attributeMap == null || attributeMap.isEmpty() || !attributeMap.containsKey(attribute)) {
            validationResult.setValid(false);
            addFailureReason(validationResult, attribute, ERROR_CODE_ATTRIBUTE_NOT_FOUND);
        } else if (StringUtils.isBlank(attributeMap.get(attribute))) {
            validationResult.setValid(false);
            addFailureReason(validationResult, attribute, ERROR_CODE_ATTRIBUTE_VALUE_EMPTY);
        }
    }

    private void addFailureReason(ValidationResult validationResult, String attribute,
                                  AuthAttributeHandlerConstants.ErrorMessages reason) {

        validationResult.getValidationFailureReasons()
                .add(new ValidationFailureReason(attribute, reason.getCode(), reason.getMessage()));
    }
}
