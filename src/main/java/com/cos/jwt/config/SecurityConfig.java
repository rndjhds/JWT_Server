package com.cos.jwt.config;


import com.cos.jwt.jwt.JwtAuthenticationFilter;
import com.cos.jwt.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;
    private final MemberRepository memberRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // 뒤 클래스전에 앞에 필터적용
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.
                .and()
                .addFilter(corsFilter) // @CrossOrigin은 생성한 클래스인 CorsConfig의 CorsFiler와 같은 기능을 한다 하지만 인증이 필요없는 URI에서만 사용,
                // 인증이 필요한 URI에도 @CrossOrigin과 같은 기능을 사용할려면 시큐리티 필터에 등록
                .formLogin().disable() // 폼태그  로그인 사용 X
                .httpBasic().disable() // 기본적인 http 인증방식(HTTP header에 Authorization에 id와 password를 들고 사용하는 인증 방법) 사용X
                // http 인증 방식을 사용하여 동일 출처 정책에서 발생하는 js 쿠키 전달 http only 문제를 해결
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // formLogin()이 disable이기 떄문에 login이 작동을 안해서 이 필터로 대체한다.
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), memberRepository))
                // AuthenticationManager를 파라미터로 꼭 넘겨 줘야한다.
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
