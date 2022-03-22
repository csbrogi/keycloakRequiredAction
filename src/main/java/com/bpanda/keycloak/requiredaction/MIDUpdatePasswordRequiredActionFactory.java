package com.bpanda.keycloak.requiredaction;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MIDUpdatePasswordRequiredActionFactory implements RequiredActionFactory {

    private static final MIDUpdatePassword SINGLETON = new MIDUpdatePassword();
    @Override
    public String getDisplayText() {
        return "MID Update Password";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return MIDUpdatePassword.PROVIDER_ID;
    }
}
