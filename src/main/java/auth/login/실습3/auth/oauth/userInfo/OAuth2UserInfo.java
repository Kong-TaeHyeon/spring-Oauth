package auth.login.실습3.auth.oauth.userInfo;

import auth.login.실습3.member.Member;

import java.util.Map;

public record OAuth2UserInfo(
        String name,
        String email,
        String profile
) {
    public static OAuth2UserInfo of(String registrationId, Map<String, Object> attributes) {
        return switch (registrationId) {
            case "kakao" -> ofKaKao(attributes);
            default -> throw new IllegalStateException("Unexpected value: " + registrationId);
        };
    }
    
    private static OAuth2UserInfo ofKaKao(Map<String, Object> attributes) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");

        return new OAuth2UserInfo(
                (String) profile.get("nickname"),
                (String) account.get("email"),
                (String) profile.get("profile_image_url")
        );
    }

    public Member toEntity() {
        return Member.builder()
                .name(name)
                .email(email)
                .role("ROLE_GUEST")
                .build();
    }


}
