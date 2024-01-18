package kr.co.ooweat.auth.ui;

import javax.servlet.http.HttpServletRequest;
import kr.co.ooweat.auth.application.AuthService;
import kr.co.ooweat.auth.domain.repository.support.AuthorizationExtractor;
import javax.validation.constraints.NotEmpty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthController {
    
    private final AuthService authService;
    
    public AuthController(final AuthService authService) {
        this.authService = authService;
    }
    
    //유효한가?
    @GetMapping("/certification")
    public void verifyToken(final HttpServletRequest request) {
        String token = AuthorizationExtractor.extract(request);
        authService.verifyToken(token);
    }
    
/*    @GetMapping("/login")
    public LoginResponse login(@RequestParam @NotEmpty final String code) {
        return authService.login(code);
    }*/
    
}
