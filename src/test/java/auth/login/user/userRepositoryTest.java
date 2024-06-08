package auth.login.user;

import auth.login.실습2.UserRepository;
import auth.login.실습2.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;


@DataJpaTest
public class userRepositoryTest {
    private UserRepository userRepository;
    private UserService userService;
}
