/*
 * Copyright (c) 2014-2025, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.carbon.identity.application.authenticator.basicauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.PasswordOnboardExecutor;
import org.wso2.carbon.identity.application.authenticator.basicauth.attribute.handler.BasicAuthAuthAttributeHandler;
import org.wso2.carbon.identity.auth.attribute.handler.AuthAttributeHandler;
import org.wso2.carbon.identity.captcha.exception.CaptchaServerException;
import org.wso2.carbon.identity.captcha.provider_mgt.service.CaptchaConfigService;
import org.wso2.carbon.identity.captcha.util.CaptchaConstants;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.user.registration.engine.graph.Executor;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

@Component(
        name = "identity.application.authenticator.basicauth.component",
        immediate = true)
public class BasicAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(BasicAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    public static RealmService getRealmService() {

        return realmService;
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service");
        BasicAuthenticatorServiceComponent.realmService = realmService;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            buildReCaptchaFilterProperties();
            BasicAuthenticator basicAuth = new BasicAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), basicAuth, null);

            BasicAuthAuthAttributeHandler authAttributeHandler = new BasicAuthAuthAttributeHandler();
            ctxt.getBundleContext().registerService(AuthAttributeHandler.class.getName(), authAttributeHandler, null);

            PasswordOnboardExecutor pwdOnboardRegExecutor = new PasswordOnboardExecutor();
            ctxt.getBundleContext().registerService(Executor.class.getName(), pwdOnboardRegExecutor, null);

            if (log.isDebugEnabled()) {
                log.info("BasicAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("BasicAuthenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("BasicAuthenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        BasicAuthenticatorServiceComponent.realmService = null;
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        BasicAuthenticatorDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        BasicAuthenticatorDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "MultiAttributeLoginService",
            service = MultiAttributeLoginService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetMultiAttributeLoginService")
    protected void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        BasicAuthenticatorDataHolder.getInstance().setMultiAttributeLogin(multiAttributeLogin);
    }

    protected void unsetMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        BasicAuthenticatorDataHolder.getInstance().setMultiAttributeLogin(null);
    }

    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the configuration manager in basic authenticator bundle.");
        }
        BasicAuthenticatorDataHolder.getInstance().setConfigurationManager(configurationManager);
    }

    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the configuration manager in basic authenticator bundle.");
        }
        BasicAuthenticatorDataHolder.getInstance().setConfigurationManager(null);
    }

    @Reference(
            name = "identity.captcha.config.service",
            service = CaptchaConfigService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCaptchaConfigService"
    )
    protected void setCaptchaConfigService(CaptchaConfigService captchaConfigService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Captcha Config Service in basic authenticator bundle.");
        }
        BasicAuthenticatorDataHolder.getInstance().setCaptchaConfigService(captchaConfigService);
    }

    protected void unsetCaptchaConfigService(CaptchaConfigService captchaConfigService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Captcha Config Service in basic authenticator bundle.");
        }
        BasicAuthenticatorDataHolder.getInstance().setCaptchaConfigService(null);
    }
    /**
     * Read the captcha-config.properties file located in repository/conf/identity directory and set the
     * configurations required to enable recaptcha in the Data holder.
     */
    private void buildReCaptchaFilterProperties() throws CaptchaServerException {

        CaptchaConfigService captchaConfigService = BasicAuthenticatorDataHolder.getInstance().getCaptchaConfigService();

        BasicAuthenticatorDataHolder.getInstance().setRecaptchaConfigs(
                captchaConfigService.getActiveCaptchaProviderConfig());

    }

    /**
     * Resolves site-key, secret-key and any other property if they are configured using secure vault.
     *
     * @param properties    Loaded reCaptcha properties.
     */
    private void resolveSecrets(Properties properties) {

        SecretResolver secretResolver = SecretResolverFactory.create(properties);
        // Iterate through whole config file and find encrypted properties and resolve them
        if (secretResolver != null && secretResolver.isInitialized()) {
            for (Map.Entry<Object, Object> entry : properties.entrySet()) {
                String key = entry.getKey().toString();
                String value = entry.getValue().toString();
                if (value != null) {
                    value = MiscellaneousUtil.resolve(value, secretResolver);
                }
                properties.put(key, value);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret Resolver is not present. Will not resolve encryptions for captcha");
            }
        }

    }
}
