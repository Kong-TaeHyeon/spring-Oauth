package auth.login.실습3;



import auth.login.실습2.JwtService2;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JWTService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String userId = authentication.getName();

        log.info("userId = {}", userId);


        String token = jwtService.createToken(authentication, "ROLE_ADMIN");
        String redirectUrl = UriComponentsBuilder.fromUriString("/auth/success")
                .queryParam("accessToken", token)
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}
