package auth.login.실습2.user;

import auth.login.실습2.dto.UserRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

//@RestController
//@RequestMapping("/api/user")
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<User> signUp(@RequestBody UserRequest userRequest) {
        return new ResponseEntity<>(userService.signUp(userRequest.getEmail(), userRequest.getPassword()), HttpStatus.CREATED);
    }

    @PostMapping("signin")
    public ResponseEntity<String> signIn(@RequestBody UserRequest userRequest) {
        String token = userService.signIn(userRequest.getEmail(), userRequest.getPassword());
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<List<User>> getUser() {
        return new ResponseEntity<>(userService.getUsers(), HttpStatus.OK);
    }

}
