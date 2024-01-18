package kr.co.ooweat.auth.application;

import kr.co.ooweat.auth.domain.repository.support.JwtTokenProvider;
import kr.co.ooweat.auth.ui.dto.LoginResponse;
import kr.co.ooweat.member.domain.Member;
import kr.co.ooweat.member.domain.MemberRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
@Transactional(readOnly = true)
public class AuthService {
    
    private final MemberRepository members;
    private final JwtTokenProvider jwtTokenProvider;
    
    public AuthService(final MemberRepository members,
        final JwtTokenProvider jwtTokenProvider) {
        this.members = members;
        this.jwtTokenProvider = jwtTokenProvider;
    }
    
    //토큰 유효성
    public void verifyToken(final String token) {
        jwtTokenProvider.validateToken(token);
    }

    LoginResponse login(final String userId, final String token) {
        Member member = members.getByUserId(userId);
        
        boolean isFirstLogin = member.isFirstLogin();
        member.firstLogin(token);
        
        return LoginResponse.builder()
            .token(jwtTokenProvider.createToken(String.valueOf(member.getUserId())))
            .firstLogin(isFirstLogin)
            .build();
    }
}
