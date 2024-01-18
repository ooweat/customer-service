package kr.co.ooweat.auth.ui;

import kr.co.ooweat.auth.domain.repository.support.AuthorizationExtractor;
import kr.co.ooweat.auth.domain.repository.support.JwtTokenProvider;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.servlet.HandlerInterceptor;

public class AuthenticationInterceptor implements HandlerInterceptor {

    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationInterceptor(final JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response,
                             final Object handler) {
        //CORS
        if (CorsUtils.isCorsRequest(request)) {
            return true;
        }
        //Token 값 매칭
        jwtTokenProvider.validateToken(AuthorizationExtractor.extract(request));
        return true;
    }
}
