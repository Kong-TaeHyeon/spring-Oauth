package auth.login;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


@RestController
public class LoginController {
    @Value("${kakao.key}")
    private String kakaoApiKey;

    @GetMapping("/oauth2/kakao")
    public void redirectKaKaoLogin(HttpServletResponse response) throws IOException {
        String redirectURI = "https://kauth.kakao.com/oauth/authorize?client_id=" + kakaoApiKey +
                "&redirect_uri=" + "http://localhost:8080/login/oauth2/kakao" +
                "&response_type=code";

        System.out.println("작동");

        response.sendRedirect(redirectURI);
    }

    @GetMapping("/login/oauth2/kakao")
    public String sendToKaKao(@RequestParam("code") String code) {
        System.out.println(code);
        return "Ok";
    }

}
