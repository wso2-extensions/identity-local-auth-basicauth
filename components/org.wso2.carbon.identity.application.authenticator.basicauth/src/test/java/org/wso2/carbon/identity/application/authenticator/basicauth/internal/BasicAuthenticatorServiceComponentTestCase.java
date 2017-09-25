/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.basicauth.internal;

import org.apache.commons.logging.Log;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.user.core.service.RealmService;

import java.lang.reflect.Field;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doAnswer;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

public class BasicAuthenticatorServiceComponentTestCase {

    private String debugMsg;
    private RealmService mockRealmService;
    private BasicAuthenticatorServiceComponent basicAuthenticatorServiceComponent;
    private ComponentContext mockComponentContext;
    private Log mockedLog;

    @BeforeTest
    public void setup() {

        basicAuthenticatorServiceComponent = new BasicAuthenticatorServiceComponent();
    }

    @Test
    public void setRealmTestCase() throws NoSuchFieldException, IllegalAccessException {

        mockedLog = mock(Log.class);
        mockRealmService = mock(RealmService.class);

        enableDebugLogs(mockedLog);
        getDebugMessage(mockedLog);

        basicAuthenticatorServiceComponent.setRealmService(mockRealmService);
        assertEquals(debugMsg, "Setting the Realm Service");
        assertNotNull(BasicAuthenticatorServiceComponent.getRealmService());
    }

    @Test
    public void deactivateTestCase() throws NoSuchFieldException, IllegalAccessException {

        mockedLog = mock(Log.class);
        mockComponentContext = mock(ComponentContext.class);

        when(mockedLog.isDebugEnabled()).thenReturn(true);
        enableDebugLogs(mockedLog);

        doAnswer(new Answer<Object>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {

                debugMsg = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockedLog).info(anyString());

        basicAuthenticatorServiceComponent.deactivate(mockComponentContext);
        assertEquals(debugMsg, "BasicAuthenticator bundle is deactivated");
    }

    @Test
    public void unSetRealmTestCase() throws NoSuchFieldException, IllegalAccessException {

        mockedLog = mock(Log.class);
        enableDebugLogs(mockedLog);
        getDebugMessage(mockedLog);

        mockRealmService = mock(RealmService.class);
        basicAuthenticatorServiceComponent.unsetRealmService(mockRealmService);

        assertEquals(debugMsg, "UnSetting the Realm Service");
    }

    private static void enableDebugLogs(final Log mockedLog) throws NoSuchFieldException, IllegalAccessException {

        Field field = BasicAuthenticatorServiceComponent.class.getDeclaredField("log");
        field.setAccessible(true);
        field.set(null, mockedLog);
    }

    private void getDebugMessage(Log mockedLog) {

        doAnswer(new Answer<Object>() {
            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {

                debugMsg = (String) invocation.getArguments()[0];
                return null;
            }
        }).when(mockedLog).debug(anyString());
    }

}
