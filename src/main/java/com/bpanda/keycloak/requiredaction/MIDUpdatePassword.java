package com.bpanda.keycloak.requiredaction;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MIDUpdatePassword implements RequiredActionProvider {
    public static String PROVIDER_ID = "MIDUpdatePassword";
    private static final Logger log = LoggerFactory.getLogger(MIDUpdatePassword.class);

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
//        UserModel user = context.getAuthenticationSession().getAuthenticatedUser();
//        Optional<String> reqActionSet = user.getRequiredActionsStream().filter(r -> PROVIDER_ID.equals(r)).findFirst();
//        if (!reqActionSet.isPresent()) {
//            user.addRequiredAction(PROVIDER_ID);
//        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
//        Response challenge = context.form().setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername()).createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
//        context.challenge(challenge);
//
        LoginFormsProvider form = context.form();
        form.setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername());
        context.challenge(form.createForm("mid-update-password.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        event.event(EventType.UPDATE_CREDENTIAL);
        event.detail(Details.CREDENTIAL_TYPE, PasswordCredentialModel.PASSWORD);
        EventBuilder deprecatedEvent = event.clone().event(EventType.UPDATE_PASSWORD);

        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");
        log.info(String.format("processAction user: %s", user.getUsername()));

        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_CREDENTIAL_ERROR)
                .client(authSession.getClient())
                .user(authSession.getAuthenticatedUser());
        EventBuilder deprecatedErrorEvent = errorEvent.clone().event(EventType.UPDATE_PASSWORD_ERROR);

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD, Messages.MISSING_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_MISSING);
            deprecatedErrorEvent.error(Errors.PASSWORD_MISSING);
            log.error("User: " + user.getUsername() +" Password is missing");
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD_CONFIRM, Messages.NOTMATCH_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            deprecatedErrorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            log.error("User: " + user.getUsername() +" Passwords do not match");
            return;
        }

        if ("on".equals(formData.getFirst("logout-sessions"))) {
            AuthenticatorUtil.logoutOtherSessions(context);
        }

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
            context.success();
            deprecatedEvent.success();
        } catch (ModelException me) {
            errorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
            deprecatedErrorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(me.getMessage(), me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
        } catch (Exception ape) {
            errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            deprecatedErrorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
        }
    }

    @Override
    public void close() {

    }

}
