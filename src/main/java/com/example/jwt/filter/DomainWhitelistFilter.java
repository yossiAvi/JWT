package com.example.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.List;

@Component
public class DomainWhitelistFilter extends OncePerRequestFilter {

    private final List<String> allowedDomains;

    public DomainWhitelistFilter(@Value("${jwt.allowed-domains}") List<String> allowedDomains) {
        this.allowedDomains = allowedDomains;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String origin = request.getHeader("Origin");
        String referer = request.getHeader("Referer");

        String domainToCheck = resolveDomain(origin, referer);

        if (domainToCheck == null || !isAllowed(domainToCheck)) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"Domain not whitelisted\",\"domain\":\""
                + (domainToCheck != null ? domainToCheck : "none") + "\"}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Prefer Origin (no path); fall back to Referer (strip path component).
     */
    private String resolveDomain(String origin, String referer) {
        if (origin != null && !origin.isBlank()) {
            return origin.trim();
        }
        if (referer != null && !referer.isBlank()) {
            try {
                URI uri = new URI(referer.trim());
                return uri.getScheme() + "://" + uri.getAuthority();
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private boolean isAllowed(String domain) {
        return allowedDomains.stream()
                .anyMatch(allowed -> allowed.equalsIgnoreCase(domain));
    }
}
