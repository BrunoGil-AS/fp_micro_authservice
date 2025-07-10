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

import lombok.extern.java.Log;

/**
 * Controller responsible for handling application errors and rendering a user-friendly error page.
 * <p>
 * This controller intercepts requests to the "/error" endpoint and provides detailed error information
 * to the view, including HTTP status codes, error messages, and request parameters. It also customizes
 * the error response based on the type of error (e.g., 404 Not Found) and the user's authentication status.
 * <p>
 * For OAuth2-related errors, additional context is provided, such as client ID, redirect URI, and PKCE flow details.
 * All relevant information is added to the model for display in the error view.
 * <p>
 * Logging is performed at various levels (info, warning, severe) to aid in debugging and monitoring error occurrences.
 *
 * @author bruno.gil
 * @see org.springframework.boot.web.servlet.error.ErrorController
 */
@Controller
@Log
public class AuthErrorController implements ErrorController {

    @GetMapping("/error")
    public String handleError(
            HttpServletRequest request,
            Model model,
            @RequestParam Map<String, String> allParams) {
        
        log.info("Handling error request - Path: " + request.getRequestURI());
        
        // Get error information
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        String errorMessage = (String) request.getAttribute("javax.servlet.error.message");
        String errorPath = (String) request.getAttribute("javax.servlet.error.request_uri");
        
        // Check if user is authenticated
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser");
        
        // Handle 404 errors differently
        if (statusCode != null && statusCode == 404) {
            log.warning("404 Not Found - Requested path: " + errorPath + " - User authenticated: " + isAuthenticated);
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
        
        // Log error details for debugging
        log.severe("Error occurred - Status: " + statusCode + ", Message: " + errorMessage + ", Path: " + errorPath);
        if (!allParams.isEmpty()) {
            log.info("Request parameters: " + allParams);
        }
        
        // If it's an OAuth2 related error, show specific information
        if (allParams.containsKey("response_type")) {
            log.warning("OAuth2 authorization error detected - Client ID: " + allParams.get("client_id") + 
                       ", Redirect URI: " + allParams.get("redirect_uri"));
            model.addAttribute("oauthError", true);
            model.addAttribute("clientId", allParams.get("client_id"));
            model.addAttribute("redirectUri", allParams.get("redirect_uri"));
            model.addAttribute("scope", allParams.get("scope"));
            
            // If there's a code_challenge, it's PKCE
            if (allParams.containsKey("code_challenge")) {
                log.info("PKCE flow detected in OAuth2 error - Code challenge method: " + 
                        allParams.get("code_challenge_method"));
                model.addAttribute("pkceFlow", true);
                model.addAttribute("codeChallenge", allParams.get("code_challenge"));
                model.addAttribute("codeChallengeMethod", allParams.get("code_challenge_method"));
            }
        }
        
        log.info("Returning error view for status code: " + statusCode);
        return "error"; // Returns the error.html view
    }
}
