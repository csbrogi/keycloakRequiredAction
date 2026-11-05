package com.bpanda.keycloak.requiredaction;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class RequiredActionFactoriesTest {

    @Test
    void registrationFactory() {
        MIDRegistrationRequiredActionFactory factory = new MIDRegistrationRequiredActionFactory();

        assertEquals("MIDRegistration", factory.getId());
        assertEquals("MID Registration", factory.getDisplayText());
        RequiredActionProvider provider = factory.create(null);
        assertInstanceOf(MIDRegistrationProvider.class, provider);
        assertSame(provider, factory.create(null));
    }

    @Test
    void accountManagerRegistrationFactory() {
        MIDAccountManagerRegistrationRequiredActionFactory factory = new MIDAccountManagerRegistrationRequiredActionFactory();

        assertEquals("MIDAccountManagerRegistration", factory.getId());
        assertEquals("MID Accountmanager Registration", factory.getDisplayText());
        assertInstanceOf(MIDAccountManagerRegistrationProvider.class, factory.create(null));
    }

    @Test
    void updatePasswordFactory() {
        MIDUpdatePasswordRequiredActionFactory factory = new MIDUpdatePasswordRequiredActionFactory();

        assertEquals("MIDUpdatePassword", factory.getId());
        assertEquals("MID Update Password", factory.getDisplayText());
        assertInstanceOf(MIDUpdatePassword.class, factory.create(null));
    }

    @Test
    void lifecycleMethodsDoNotFail() {
        MIDRegistrationRequiredActionFactory factory = new MIDRegistrationRequiredActionFactory();
        factory.init(null);
        factory.postInit(null);
        factory.close();
    }
}
