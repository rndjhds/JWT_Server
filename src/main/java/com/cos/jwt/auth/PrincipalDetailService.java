package com.cos.jwt.auth;

import com.cos.jwt.model.Member;
import com.cos.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8082/login => formLogin()을 사용하지 않기 때문에 동작하지 않음
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {
    private final MemberRepository memberRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailService의 loadUserByUsername 실행");
        Member findMember = memberRepository.findByUsername(username);
        System.out.println("memberEntity = " + findMember);
        return new PrincipalDetails(findMember);
    }
}
