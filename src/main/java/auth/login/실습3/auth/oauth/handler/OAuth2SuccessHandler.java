package auth.login.실습3.auth.oauth.handler;



import auth.login.실습3.auth.jwt.JWTService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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
        String token = jwtService.createToken(authentication);

        // 쿠키를 사용해서 토큰 전달.
        Cookie cookie = new Cookie("token", token);
        response.addCookie(cookie);

        // URL 을 사용해서 토큰 전달.
        String redirectUrl = UriComponentsBuilder.fromUriString("/auth/success")
                .queryParam("accessToken", token)
                .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}
