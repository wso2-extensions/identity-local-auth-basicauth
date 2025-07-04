/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.PASSWORD_KEY;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;

/**
 * This class is responsible for onboarding the password of the user.
 */
public class PasswordOnboardExecutor implements Executor {

    public static final String PASSWORD_ONBOARD_EXECUTOR = "PasswordOnboardExecutor";

    public String getName() {

        return PASSWORD_ONBOARD_EXECUTOR;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        ExecutorResponse response;
        if (flowExecutionContext.getUserInputData() == null || StringUtils.isEmpty(flowExecutionContext.getUserInputData().get(PASSWORD_KEY))) {
            response = new ExecutorResponse(STATUS_USER_INPUT_REQUIRED);
            response.setRequiredData(Collections.singletonList(PASSWORD_KEY));
            return response;
        } else {
            // Todo enforce password policies.
            response = new ExecutorResponse(STATUS_COMPLETE);
            Map<String, char[]> credentials =
                    Collections.singletonMap(PASSWORD_KEY, flowExecutionContext.getUserInputData().
                            get(PASSWORD_KEY).toCharArray());
            response.setUserCredentials(credentials);
        }
        return response;
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(USERNAME_CLAIM_URI);
        initiationData.add(PASSWORD_KEY);
        return initiationData;
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) {

        return null;
    }
}
