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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.osgi.service.component.ComponentContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.captcha.exception.CaptchaServerException;
import org.wso2.carbon.identity.captcha.provider_mgt.service.CaptchaConfigService;
import org.wso2.carbon.identity.captcha.provider_mgt.service.impl.CaptchaConfigServiceImpl;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Properties;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

public class BasicAuthenticatorServiceComponentTestCase {

    private RealmService mockRealmService;
    private BasicAuthenticatorServiceComponent basicAuthenticatorServiceComponent;
    private ComponentContext mockComponentContext;
    private ConfigurationManager mockConfigManager;

    @BeforeMethod
    public void init() {

        basicAuthenticatorServiceComponent = new BasicAuthenticatorServiceComponent();

        mockRealmService = mock(RealmService.class);
        mockComponentContext = mock(ComponentContext.class);
    }

    @Test
    public void setRealmTestCase() throws NoSuchFieldException, IllegalAccessException {
        basicAuthenticatorServiceComponent.setRealmService(mockRealmService);
        assertNotNull(BasicAuthenticatorServiceComponent.getRealmService());
    }

    @Test
    public void deactivateTestCase() throws NoSuchFieldException, IllegalAccessException {
        mockComponentContext = mock(ComponentContext.class);
        basicAuthenticatorServiceComponent.deactivate(mockComponentContext);
    }

    @Test
    public void unSetRealmTestCase() throws NoSuchFieldException, IllegalAccessException {
        mockRealmService = mock(RealmService.class);
        basicAuthenticatorServiceComponent.unsetRealmService(mockRealmService);
        assertNull(BasicAuthenticatorServiceComponent.getRealmService());
    }

    @Test
    public void activateTestCase() {

        ComponentContext componentContext = mock(ComponentContext.class, Mockito.RETURNS_DEEP_STUBS);
        Properties captchaConfig = new Properties();
        captchaConfig.setProperty("captchaEnabled", "true");
        captchaConfig.setProperty("captchaProvider", "testCaptcha");
        captchaConfig.setProperty("reCaptchaSiteKey", "testSiteKey");
        captchaConfig.setProperty("reCaptchaSiteSecret", "testSiteSecret");

        try (MockedStatic<BasicAuthenticatorDataHolder> mockedStatic =
                     mockStatic(BasicAuthenticatorDataHolder.class)) {

            BasicAuthenticatorDataHolder mockDataHolder = mock(BasicAuthenticatorDataHolder.class);

            // Stub methods on the mock
            CaptchaConfigService mockCaptchaConfigService = mock(CaptchaConfigService.class);
            when(mockCaptchaConfigService.getActiveCaptchaProviderConfig()).thenReturn(
                    captchaConfig); // or a real config if needed

            when(mockDataHolder.getCaptchaConfigService()).thenReturn(mockCaptchaConfigService);

            // Return mockDataHolder when getInstance() is called
            mockedStatic.when(BasicAuthenticatorDataHolder::getInstance).thenReturn(mockDataHolder);
            basicAuthenticatorServiceComponent.activate(componentContext);

            Mockito.verify(componentContext, Mockito.atLeastOnce()).getBundleContext();
        }
    }

    @Test
    public void registerConfigurationManager() {

        mockConfigManager = mock(ConfigurationManager.class);
        basicAuthenticatorServiceComponent.registerConfigurationManager(mockConfigManager);
        assertNotNull(BasicAuthenticatorDataHolder.getInstance().getConfigurationManager());
    }

    @Test
    public void unregisterConfigurationManager() {

        mockConfigManager = mock(ConfigurationManager.class);
        basicAuthenticatorServiceComponent.unregisterConfigurationManager(mockConfigManager);
        assertNull(BasicAuthenticatorDataHolder.getInstance().getConfigurationManager());
    }
}
