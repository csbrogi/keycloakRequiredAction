package com.bpanda.keycloak.requiredaction;

import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.function.Consumer;

public class MIDRegistrationProvider implements RequiredActionProvider {
    public static String PROVIDER_ID = "MIDRegistration";

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext requiredActionContext) {
        requiredActionContext.challenge(createForm(requiredActionContext, null));
    }

    @Override
    public void processAction(RequiredActionContext context) {

        UserModel user = context.getUser();

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String lastName = formData.getFirst("lastName");
        String firstName = formData.getFirst("firstName");
        String preferredLanguage = formData.getFirst("preferredLanguage");

        if (!checkInputField(lastName, context, "lastName") ||
                !checkInputField(firstName, context, "firstName")) {
            return;
        }

        user.setLastName(lastName);
        user.setFirstName(firstName);
        user.setSingleAttribute("registered", "true");
        if (null != preferredLanguage && !"".equals(preferredLanguage)) {
            user.setSingleAttribute("preferredLanguage", preferredLanguage);
            user.setSingleAttribute("locale", preferredLanguage);
        }
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
//        String an = authSession.getAuthNote(END_AFTER_REQUIRED_ACTIONS);
//        an = authSession.getAuthNote(SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS);

        context.success();
    }

    private boolean checkInputField(String field, RequiredActionContext context, String fieldName) {
        if (field == null || field.length() == 0) {
            context.challenge(createForm(context, form -> form.addError(new FormMessage(fieldName, "Invalid input"))));
            return false;
        }
        return true;
    }

    @Override
    public void close() {

    }

    private Response createForm(RequiredActionContext context, Consumer<LoginFormsProvider> formConsumer) {
        LoginFormsProvider form = context.form();
        UserModel user = context.getUser();
        form.setAttribute("email", user.getEmail());
        form.setAttribute("firstName", user.getFirstName());
        form.setAttribute("lastName", user.getLastName());
        form.setAttribute("preferredLanguage", user.getAttributeStream("preferredLanguage").findFirst().orElse(""));
//        String mobileNumber = context.getUser().getFirstAttribute(MOBILE_NUMBER_FIELD);
//        form.setAttribute(MOBILE_NUMBER_FIELD, mobileNumber == null ? "" : mobileNumber);
//
//        if (formConsumer != null) {
//            formConsumer.accept(form);
//        }

        return form.createForm("mid_registration.ftl");
    }

}
