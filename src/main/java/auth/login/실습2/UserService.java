package auth.login.실습2;

import org.springframework.stereotype.Service;

@Service
public class UserService {

    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User signUp(String email, String password) {
        User user = new User(email, password, "ADMIN");
        return userRepository.save(user);
    }
}
