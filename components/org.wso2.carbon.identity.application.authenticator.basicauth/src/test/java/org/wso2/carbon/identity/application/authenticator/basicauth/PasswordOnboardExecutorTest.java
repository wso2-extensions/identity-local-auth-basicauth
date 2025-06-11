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

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.PASSWORD;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;

/**
 * Unit tests for PasswordOnboardExecutor.
 */
public class PasswordOnboardExecutorTest {

    @Mock
    private FlowExecutionContext mockFlowExecContext;

    private PasswordOnboardExecutor passwordOnboardExecutor;

    @BeforeMethod
    public void setUp() {

        openMocks(this);
        passwordOnboardExecutor = new PasswordOnboardExecutor();
    }

    @Test
    public void testPasswordRequiredState() throws Exception {

        Map<String, String> userInputData = new HashMap<>();
        when(mockFlowExecContext.getUserInputData()).thenReturn(userInputData);

        ExecutorResponse response = passwordOnboardExecutor.execute(mockFlowExecContext);
        assertEquals(response.getResult(), STATUS_USER_INPUT_REQUIRED);
        assertEquals(response.getRequiredData().size(), 1);
        assertEquals(response.getRequiredData().get(0), PASSWORD);
    }

    @Test
    public void testPasswordProvidedState() throws Exception {

        Map<String, String> userInputData = new HashMap<>();
        userInputData.put(PASSWORD, "P@ssw0rd");

        when(mockFlowExecContext.getUserInputData()).thenReturn(userInputData);

        ExecutorResponse response = passwordOnboardExecutor.execute(mockFlowExecContext);
        assertEquals(response.getResult(), STATUS_COMPLETE);
        assertNotNull(response.getUserCredentials().get(PASSWORD));
    }
}
