package auth.login;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
@Slf4j
public class ExceptionHandler {
    public void handleUserNotFindException(Exception ex) {
      log.error("User Not Find Exception", ex);
    }

}
