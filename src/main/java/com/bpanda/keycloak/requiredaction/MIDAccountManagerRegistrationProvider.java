package com.bpanda.keycloak.requiredaction;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

public class MIDAccountManagerRegistrationProvider extends  MIDRegistrationProvider implements RequiredActionProvider {
    public static String PROVIDER_ID = "MIDAccountManagerRegistration";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
//        UserModel user = context.getUser();
//        if (user.getFirstAttribute("registered") == null) {
//            Optional<String> reqActionSet = user.getRequiredActionsStream().filter(r -> PROVIDER_ID.equals(r)).findFirst();
//            if (!reqActionSet.isPresent()) {
//                user.addRequiredAction(PROVIDER_ID);
//            }
//        }
    }

}
