package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class AuthErrorController implements ErrorController {

    @GetMapping("/error")
    public String handleError(
            HttpServletRequest request,
            Model model,
            @RequestParam Map<String, String> allParams) {
        
        // Get error information
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        String errorMessage = (String) request.getAttribute("javax.servlet.error.message");
        String errorPath = (String) request.getAttribute("javax.servlet.error.request_uri");
        
        // Check if user is authenticated
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser");
        
        // Handle 404 errors differently
        if (statusCode != null && statusCode == 404) {
            model.addAttribute("is404", true);
            model.addAttribute("requestedPath", errorPath);
            model.addAttribute("isAuthenticated", isAuthenticated);
            
            // For 404 errors, provide helpful navigation
            if (isAuthenticated) {
                model.addAttribute("redirectSuggestion", "Go to Dashboard");
                model.addAttribute("redirectUrl", "/");
            } else {
                model.addAttribute("redirectSuggestion", "Go to Login");
                model.addAttribute("redirectUrl", "/login");
            }
        }
        
        // Add information to model for the view
        model.addAttribute("statusCode", statusCode);
        model.addAttribute("errorMessage", errorMessage != null ? errorMessage : "No message available");
        model.addAttribute("errorPath", errorPath);
        model.addAttribute("requestParams", allParams);
        
        // Log for debugging
        System.out.println("=== AUTH ERROR DEBUG ===");
        System.out.println("Status Code: " + statusCode);
        System.out.println("Error Message: " + errorMessage);
        System.out.println("Error Path: " + errorPath);
        System.out.println("Request Parameters: " + allParams);
        System.out.println("User Authenticated: " + isAuthenticated);
        System.out.println("========================");
        
        // If it's an OAuth2 related error, show specific information
        if (allParams.containsKey("response_type")) {
            model.addAttribute("oauthError", true);
            model.addAttribute("clientId", allParams.get("client_id"));
            model.addAttribute("redirectUri", allParams.get("redirect_uri"));
            model.addAttribute("scope", allParams.get("scope"));
            
            // If there's a code_challenge, it's PKCE
            if (allParams.containsKey("code_challenge")) {
                model.addAttribute("pkceFlow", true);
                model.addAttribute("codeChallenge", allParams.get("code_challenge"));
                model.addAttribute("codeChallengeMethod", allParams.get("code_challenge_method"));
            }
        }
        
        return "error"; // Returns the error.html view
    }
}
