package auth.login.실습2.dto;


import lombok.Getter;

@Getter
public class UserRequest {
    private String email;
    private String password;

    public UserRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }
}
