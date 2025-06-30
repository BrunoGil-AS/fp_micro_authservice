package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.*;

@Controller
public class OAuth2ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public OAuth2ConsentController(RegisteredClientRepository registeredClientRepository,
                                 OAuth2AuthorizationConsentService authorizationConsentService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }

    /**
     * Shows the OAuth2 consent page
     * This page allows the user to authorize client application access
     */
    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
                         @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                         @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                         @RequestParam(OAuth2ParameterNames.STATE) String state,
                         HttpServletRequest request) {

        // Get registered client information
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }

        // Check previous consent
        OAuth2AuthorizationConsent currentAuthorizationConsent = 
            this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());

        Set<String> authorizedScopes = currentAuthorizationConsent != null ? 
            currentAuthorizationConsent.getScopes() : Collections.emptySet();

        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();

        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (authorizedScopes.contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else {
                scopesToApprove.add(requestedScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName() != null ? 
            registeredClient.getClientName() : registeredClient.getClientId());
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("requestFullUrl", request.getRequestURL().toString() + "?" + request.getQueryString());

        return "consent";
    }

    /**
     * Adds friendly descriptions for scopes
     */
    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));
        }
        return scopeWithDescriptions;
    }

    /**
     * Inner class to represent a scope with description
     */
    public static class ScopeWithDescription {
        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, scope);
        }

        private static final Map<String, String> scopeDescriptions = Map.of(
            "openid", "Access to identity information",
            "profile", "Access to profile information", 
            "api.read", "Read access to API",
            "api.write", "Write access to API",
            "gateway.read", "Read access to gateway",
            "gateway.write", "Write access to gateway"
        );
    }
}
