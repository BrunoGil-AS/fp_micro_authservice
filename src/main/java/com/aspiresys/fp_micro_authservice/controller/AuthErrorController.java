package com.aspiresys.fp_micro_authservice.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@Controller
public class AuthErrorController implements ErrorController {

    @GetMapping("/error")
    public String handleError(
            HttpServletRequest request,
            Model model,
            @RequestParam Map<String, String> allParams) {
        
        // Obtener información del error
        Integer statusCode = (Integer) request.getAttribute("javax.servlet.error.status_code");
        String errorMessage = (String) request.getAttribute("javax.servlet.error.message");
        String errorPath = (String) request.getAttribute("javax.servlet.error.request_uri");
        
        // Agregar información al modelo para la vista
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
