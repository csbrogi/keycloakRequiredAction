package com.bpanda.keycloak.requiredaction;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;


public class MIDUpdatePassword implements RequiredActionProvider {
    public static String PROVIDER_ID = "MIDUpdatePassword";

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
        event.event(EventType.UPDATE_PASSWORD);
        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");
        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR).client(authSession.getClient()).user(authSession.getAuthenticatedUser());
        Response challenge;
        if (passwordNew == null || passwordNew.length() == 0) {
            challenge = context.form().setAttribute("username", authSession.getAuthenticatedUser().getUsername()).addError(new FormMessage("password", "missingPasswordMessage")).createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error("password_missing");
        } else if (!passwordNew.equals(passwordConfirm)) {
            challenge = context.form().setAttribute("username", authSession.getAuthenticatedUser().getUsername()).addError(new FormMessage("password-confirm", "notMatchPasswordMessage")).createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error("password_confirm_error");
        } else {
            if (MIDUpdatePassword.PROVIDER_ID.equals(authSession.getClientNote("kc_action_executing")) && "on".equals(formData.getFirst("logout-sessions"))) {
//                ((List)session.sessions().getUserSessionsStream(realm, user).filter((s) -> {
//                    return !Objects.equals(s.getId(), authSession.getParentSession().getId());
//                }).collect(Collectors.toList())).forEach((s) -> {
//                    AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(), context.getConnection(), context.getHttpRequest().getHttpHeaders(), true);
//                });
            }

//            Response challenge;
            try {
//                authSession.
                user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
//                session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password(passwordNew, false));
                context.success();
            } catch (ModelException var13) {
                errorEvent.detail("reason", var13.getMessage()).error("password_rejected");
                challenge = context.form().setAttribute("username", authSession.getAuthenticatedUser().getUsername()).setError(var13.getMessage(), var13.getParameters()).createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
            } catch (Exception var14) {
                errorEvent.detail("reason", var14.getMessage()).error("password_rejected");
                challenge = context.form().setAttribute("username", authSession.getAuthenticatedUser().getUsername()).setError(var14.getMessage(), new Object[0]).createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
            }
        }
    }

    @Override
    public void close() {

    }

}
