package com.example.security1.config;

// 구글 로그인이 완료된 뒤의 후처리가 필요함. 1.코드받기(인증을 받았다는거), 2.엑세스토큰(사용자에 대해 접근권한을 받음)
// 3.사용자프로필 정보를 가져오고 4.그 정보를 토대로 회원가입을 자동으로 진행시키기도 함함
// 4-2 구글에서는 (이메일, 전화번호, 이름, 아이디) 밖에 없어서 집주소라던가 등급같은걸 넣어줄려면 추가적인 회원가입 창을 만들어줘야함
// 하지만 구글이 가지고 있는 기본정보로 회원가입 할수 있으면 회원가입을 자동으로 진행시킨다.

import com.example.security1.config.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화, preAuthorize 어노테이션과 postAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    //해당 메서드의 리턴되는 오브젝트가 IoC로 등록된다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // /login주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인 진행
                .defaultSuccessUrl("/")
                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
                //구글로그인이 완료된 뒤 후처리가 필요하다.
                //Tip. 코드를 받는게 아니라 액세스토큰과 사용자 프로필정보를 한번에 받는다
                //그래서 OAuth라이브러리가 편하다는것

    }
}
