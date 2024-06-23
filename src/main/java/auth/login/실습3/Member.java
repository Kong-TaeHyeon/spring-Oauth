package auth.login.실습3;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String email;

    @Column
    private String name;

    @Column
    private String role;

    @Builder
    public Member(String email, String name, String role) {
        this.email = email;
        this.name = name;
        this.role = role;
    }
}
