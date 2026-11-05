package com.bpanda.keycloak.requiredaction;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.UserModel;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MIDRegistrationProviderTest {

    private MIDRegistrationProvider provider;
    private RequiredActionContext context;
    private UserModel user;
    private LoginFormsProvider form;
    private Response response;
    private MultivaluedMap<String, String> formData;

    @BeforeEach
    void setUp() {
        provider = new MIDRegistrationProvider();
        context = mock(RequiredActionContext.class);
        user = mock(UserModel.class);
        form = mock(LoginFormsProvider.class, Answers.RETURNS_SELF);
        response = mock(Response.class);
        formData = new MultivaluedHashMap<>();
        HttpRequest request = mock(HttpRequest.class);

        when(context.getUser()).thenReturn(user);
        when(context.form()).thenReturn(form);
        when(context.getHttpRequest()).thenReturn(request);
        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(user.getUsername()).thenReturn("jdoe");
        when(form.createForm("mid_registration.ftl")).thenReturn(response);
    }

    @Test
    void providerIdAndInitiatedActionSupport() {
        assertEquals("MIDRegistration", MIDRegistrationProvider.PROVIDER_ID);
        assertEquals(InitiatedActionSupport.SUPPORTED, provider.initiatedActionSupport());
    }

    @Test
    void challengeRendersFormWithUserAttributes() {
        when(user.getEmail()).thenReturn("j@doe.com");
        when(user.getFirstName()).thenReturn("John");
        when(user.getLastName()).thenReturn("Doe");

        provider.requiredActionChallenge(context);

        verify(form).setAttribute("email", "j@doe.com");
        verify(form).setAttribute("firstName", "John");
        verify(form).setAttribute("lastName", "Doe");
        verify(context).challenge(response);
    }

    @Test
    void processActionStoresDataAndSucceeds() {
        formData.add("lastName", "Doe");
        formData.add("firstName", "John");
        formData.add("preferredLanguage", "de");

        provider.processAction(context);

        verify(user).setLastName("Doe");
        verify(user).setFirstName("John");
        verify(user).setSingleAttribute("registered", "true");
        verify(user).setSingleAttribute("preferredLanguage", "de");
        verify(user).setSingleAttribute("locale", "de");
        verify(context).success();
    }

    @Test
    void processActionWithoutLanguageSkipsLanguageAttributes() {
        formData.add("lastName", "Doe");
        formData.add("firstName", "John");

        provider.processAction(context);

        verify(user, never()).setSingleAttribute(org.mockito.ArgumentMatchers.eq("preferredLanguage"), anyString());
        verify(user, never()).setSingleAttribute(org.mockito.ArgumentMatchers.eq("locale"), anyString());
        verify(context).success();
    }

    @Test
    void processActionWithEmptyLanguageSkipsLanguageAttributes() {
        formData.add("lastName", "Doe");
        formData.add("firstName", "John");
        formData.add("preferredLanguage", "");

        provider.processAction(context);

        verify(user, never()).setSingleAttribute(org.mockito.ArgumentMatchers.eq("locale"), anyString());
        verify(context).success();
    }

    @Test
    void processActionWithMissingLastNameChallengesAgain() {
        formData.add("firstName", "John");

        provider.processAction(context);

        verify(context).challenge(response);
        verify(context, never()).success();
        verify(user, never()).setFirstName(any());
        verify(user, never()).setSingleAttribute(anyString(), anyString());
    }

    @Test
    void processActionWithEmptyFirstNameChallengesAgain() {
        formData.add("lastName", "Doe");
        formData.add("firstName", "");

        provider.processAction(context);

        verify(context).challenge(response);
        verify(context, never()).success();
        verify(user, never()).setLastName(any());
    }

    @Test
    void accountManagerProviderDoesNotEvaluateTriggersAndInheritsBehaviour() {
        MIDAccountManagerRegistrationProvider amProvider = new MIDAccountManagerRegistrationProvider();

        amProvider.evaluateTriggers(context);

        assertEquals("MIDAccountManagerRegistration", MIDAccountManagerRegistrationProvider.PROVIDER_ID);
        assertEquals(InitiatedActionSupport.SUPPORTED, amProvider.initiatedActionSupport());
        assertSame(response, form.createForm("mid_registration.ftl"));
    }
}
