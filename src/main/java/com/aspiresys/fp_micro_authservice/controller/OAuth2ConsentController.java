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
     * Muestra la página de consentimiento OAuth2
     * Esta página permite al usuario autorizar el acceso de la aplicación cliente
     */
    @GetMapping("/oauth2/consent")
    public String consent(Principal principal, Model model,
                         @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                         @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                         @RequestParam(OAuth2ParameterNames.STATE) String state,
                         HttpServletRequest request) {

        // Obtener información del cliente registrado
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Cliente no encontrado: " + clientId);
        }

        // Verificar el consentimiento previo
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
     * Agrega descripciones amigables para los scopes
     */
    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));
        }
        return scopeWithDescriptions;
    }

    /**
     * Clase interna para representar un scope con descripción
     */
    public static class ScopeWithDescription {
        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, scope);
        }

        private static final Map<String, String> scopeDescriptions = Map.of(
            "openid", "Acceso a información de identidad",
            "profile", "Acceso a información del perfil",
            "api.read", "Acceso de lectura a la API",
            "api.write", "Acceso de escritura a la API",
            "gateway.read", "Acceso de lectura al gateway",
            "gateway.write", "Acceso de escritura al gateway"
        );
    }
}
