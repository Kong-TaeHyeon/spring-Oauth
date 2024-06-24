package auth.login.실습3;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JWTService jwtService;

    private List<String> permittedUrls = Arrays.asList(
            "/api/v3/user/signup",
            "/api/v3/user/signin"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("request URI : {}", request.getRequestURI());
        if (permittedUrls.contains(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = request.getHeader("Authorization") != null ? request.getHeader("Authorization").substring(7) : null;

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            Authentication authentication = jwtService.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}
