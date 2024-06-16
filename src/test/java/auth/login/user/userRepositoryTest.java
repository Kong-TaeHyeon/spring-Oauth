package auth.login.user;

import auth.login.실습2.user.UserRepository;
import auth.login.실습2.user.UserService;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;


@DataJpaTest
public class userRepositoryTest {
    private UserRepository userRepository;
    private UserService userService;
}
