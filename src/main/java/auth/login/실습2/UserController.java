package auth.login.실습2;

import auth.login.실습2.dto.UserRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<User> signUp(@RequestBody UserRequest userRequest) {
        return new ResponseEntity<>(userService.signUp(userRequest.getEmail(), userRequest.getPassword()), HttpStatus.CREATED);
    }
}
