package auth.login.실습2.user;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class User  {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String email;

    @Column
    private String password;

    @Column
    private String role;

    public User() {}

    public User(String email, String password,String role) {
        this.email = email;
        this.password = password;
        this.role = role;
    }
}
