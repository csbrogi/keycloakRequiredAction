package com.bpanda.keycloak.requiredaction;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ModelException;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Answers;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class MIDUpdatePasswordTest {

    private MIDUpdatePassword provider;
    private RequiredActionContext context;
    private UserModel user;
    private LoginFormsProvider form;
    private Response response;
    private EventBuilder event;
    private SubjectCredentialManager credentialManager;
    private MultivaluedMap<String, String> formData;

    @BeforeEach
    void setUp() {
        provider = new MIDUpdatePassword();
        context = mock(RequiredActionContext.class);
        user = mock(UserModel.class);
        form = mock(LoginFormsProvider.class, Answers.RETURNS_SELF);
        response = mock(Response.class);
        event = mock(EventBuilder.class, Answers.RETURNS_SELF);
        credentialManager = mock(SubjectCredentialManager.class);
        formData = new MultivaluedHashMap<>();
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        HttpRequest request = mock(HttpRequest.class);

        when(context.getUser()).thenReturn(user);
        when(context.form()).thenReturn(form);
        when(context.getEvent()).thenReturn(event);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getHttpRequest()).thenReturn(request);
        when(request.getDecodedFormParameters()).thenReturn(formData);
        when(authSession.getAuthenticatedUser()).thenReturn(user);
        when(authSession.getClient()).thenReturn(mock(ClientModel.class));
        when(user.getUsername()).thenReturn("jdoe");
        when(user.credentialManager()).thenReturn(credentialManager);
        when(form.createForm("mid-update-password.ftl")).thenReturn(response);
        when(form.createResponse(UserModel.RequiredAction.UPDATE_PASSWORD)).thenReturn(response);
    }

    @Test
    void providerIdAndInitiatedActionSupport() {
        assertEquals("MIDUpdatePassword", MIDUpdatePassword.PROVIDER_ID);
        assertEquals(InitiatedActionSupport.SUPPORTED, provider.initiatedActionSupport());
    }

    @Test
    void challengeRendersCustomTemplateWithUsername() {
        provider.requiredActionChallenge(context);

        verify(form).setAttribute("username", "jdoe");
        verify(context).challenge(response);
    }

    @Test
    void missingPasswordChallengesAndReportsError() {
        formData.add("password-confirm", "x");

        provider.processAction(context);

        verify(context).challenge(response);
        verify(event, org.mockito.Mockito.atLeastOnce()).error(Errors.PASSWORD_MISSING);
        verify(context, never()).success();
        verify(credentialManager, never()).updateCredential(any());
    }

    @Test
    void blankPasswordIsTreatedAsMissing() {
        formData.add("password-new", "   ");
        formData.add("password-confirm", "   ");

        provider.processAction(context);

        verify(event, org.mockito.Mockito.atLeastOnce()).error(Errors.PASSWORD_MISSING);
        verify(context, never()).success();
    }

    @Test
    void mismatchingConfirmationChallengesAndReportsError() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret2");

        provider.processAction(context);

        verify(context).challenge(response);
        verify(event, org.mockito.Mockito.atLeastOnce()).error(Errors.PASSWORD_CONFIRM_ERROR);
        verify(context, never()).success();
        verify(credentialManager, never()).updateCredential(any());
    }

    @Test
    void validPasswordUpdatesCredentialAndSucceeds() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret1");

        provider.processAction(context);

        verify(credentialManager).updateCredential(any(UserCredentialModel.class));
        verify(context).success();
        verify(context, never()).challenge(any());
    }

    @Test
    void logoutSessionsFlagLogsOutOtherSessions() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret1");
        formData.add("logout-sessions", "on");

        try (MockedStatic<AuthenticatorUtil> util = mockStatic(AuthenticatorUtil.class)) {
            provider.processAction(context);

            util.verify(() -> AuthenticatorUtil.logoutOtherSessions(context));
        }
        verify(context).success();
    }

    @Test
    void withoutLogoutFlagOtherSessionsStayLoggedIn() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret1");

        try (MockedStatic<AuthenticatorUtil> util = mockStatic(AuthenticatorUtil.class)) {
            provider.processAction(context);

            util.verifyNoInteractions();
        }
    }

    @Test
    void modelExceptionFromPolicyChallengesWithError() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret1");
        ModelException me = new ModelException("invalidPasswordMinLengthMessage", 8);
        doThrow(me).when(credentialManager).updateCredential(any());

        provider.processAction(context);

        verify(form).setError("invalidPasswordMinLengthMessage", me.getParameters());
        verify(context).challenge(response);
        verify(event, org.mockito.Mockito.atLeastOnce()).error(Errors.PASSWORD_REJECTED);
        verify(context, never()).success();
    }

    @Test
    void unexpectedExceptionChallengesWithError() {
        formData.add("password-new", "secret1");
        formData.add("password-confirm", "secret1");
        doThrow(new IllegalStateException("boom")).when(credentialManager).updateCredential(any());

        provider.processAction(context);

        verify(form).setError("boom");
        verify(context).challenge(response);
        verify(event, org.mockito.Mockito.atLeastOnce()).error(Errors.PASSWORD_REJECTED);
        verify(context, never()).success();
    }

    @Test
    void evaluateTriggersAndCloseAreNoOps() {
        provider.evaluateTriggers(context);
        provider.close();

        verify(context, never()).challenge(any());
        verify(user, never()).addRequiredAction(anyString());
    }
}
