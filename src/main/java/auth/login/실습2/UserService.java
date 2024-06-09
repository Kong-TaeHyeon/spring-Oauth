package auth.login.실습2;

import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;
    private JwtService2 jwtService;

    public UserService(UserRepository userRepository, JwtService2 jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    public User signUp(String email, String password) {
        User user = new User(email, password, "ROLE_ADMIN");
        return userRepository.save(user);
    }

    public String signIn(String email, String password) {
        User user = userRepository.findByEmailAndPassword(email, password).orElseThrow(()-> new RuntimeException());
        return jwtService.createToken(Long.toString(user.getId()), user.getRole());
    }
}
