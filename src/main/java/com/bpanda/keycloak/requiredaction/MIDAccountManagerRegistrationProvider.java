package com.bpanda.keycloak.requiredaction;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MIDAccountManagerRegistrationProvider extends  MIDRegistrationProvider implements RequiredActionProvider {
    public static String PROVIDER_ID = "MIDAccountManagerRegistration";
    protected static final Logger log = LoggerFactory.getLogger(MIDAccountManagerRegistrationProvider.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

}
