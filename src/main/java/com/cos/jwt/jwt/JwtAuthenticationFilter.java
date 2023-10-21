package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.Member;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter가 동작을 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager; // username, password를 받아서 로그인을 시도한다.

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            // 1. username, password 받아서
            Gson gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
            Member member = gson.fromJson(request.getReader(), Member.class);
            System.out.println("로그인 시도중");
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(member.getUsername(), member.getPassword()); // 로그인을 위해서 토큰 생성
            // 폼로그인을 할경우 자동으로 해주지만 폼로그인을 사용하지 않기 때문에 직접 만들어줌

            // PrincipalDetailService의 loadUserByUsername() 메서드가 실행된 후 정상이면 authentication이 리턴됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

            // 로그인이 되었다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("PrincipalDetail = " + principalDetails.getMember().getUsername()); // 로그인이 정상적으로 되었다는 뜻
            System.out.println("PrincipalDetail = " + principalDetails.getMember().getPassword());
            // authentication 객체가 session영역에 저장을 해야하고 그 방법이 return 해주면 됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어줌

            // 2. 정상인지 로그인 시도를 해보는거예요. authenticationManager로 로그인 시도를 하면!!
            // 3. PrincipalDetailService가 호출되서 loadUserByUsername()메서드 실행

            // 4. PrincipalDetails를 세션에 담고 (권한 관리를 하기 위해서 사용함)
            // 5. JWT 토큰을 만들어서 응답해주면 됨

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 메서드가 실행됨
    // JWT 토큰을 만들어서 request요청한 사용자에세 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료 되었다는 뜻임");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 Hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰") // 토큰의 이름
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 토큰의 만료시간을 10분으로 설정(보통 30분)
                .withClaim("id", principalDetails.getMember().getId())
                .withClaim("username", principalDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer "+jwtToken);
    }
}
