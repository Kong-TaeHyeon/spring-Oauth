package auth.login.실습2;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
//@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private final JwtService2 jwtService2;
    private final CustomUserDetailsService customUserDetailsService;

    List<String> list = Arrays.asList(
            "/api/user/signup",
            "/api/user/signin",
            "/api/"
    ) ;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("URI : {}", request.getRequestURI());
        if (list.contains(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader("Authorization").startsWith("Bearer ") ? request.getHeader("Authorization").substring(7) : null;
        log.info("token: {}", token);
        log.info("User ID : {}", jwtService2.getClaim(token).get("username").toString());
        log.info("User Role : {}", jwtService2.getClaim(token).get("role").toString());

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails= customUserDetailsService.loadUserByUsername(jwtService2.getClaim(token).get("username").toString());
            log.info("userDetails Name : {} ", userDetails.getUsername());
            log.info("userDetails Role : {} ", userDetails.getAuthorities());
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        filterChain.doFilter(request, response);
    }
}
