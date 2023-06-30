package org.example.config.auth;

import lombok.RequiredArgsConstructor;
import org.example.domain.user.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;

@RequiredArgsConstructor
@EnableWebSecurity      //Spring Security 설정들을 활성화시켜준다
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.csrf().disable()
                .headers().frameOptions().disable()     //h2-console 화면을 사용하기 위해 해당 옵션들을 disable 함
                .and()
                .authorizeRequests()    //url별 권한관리를 설정
                .antMatchers("/","/css/**","/images/**",
                        "/js/**","/h2-console/**").permitAll()      //전체 권한 허가
                .antMatchers("/api/v1/**").hasRole(Role.USER.name())    //USER 권한을 가진 사람만 권한 부여
                .anyRequest().authenticated()       //설정된 값들 외의 나머지 URL들 인증된 사용자들에게만 허용(로그인한 사용자들)
                .and()
                .logout().logoutSuccessUrl("/") //로그아웃 성공 시 /주소로 이동
                .and()
                .oauth2Login().userInfoEndpoint()       //OAuth2 로그인 성공 이후 사용자 정보를 가져올 때의 설정들 담당
                .userService(customOAuth2UserService);     //소셜로그인 성공 시 후속 조치를 진행할 UserService 인터페이스 구현체 등록
    }
}
