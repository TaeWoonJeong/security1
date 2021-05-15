package com.example.security1.config.auth;

// 시큐리티가 /login 주소요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료가 되면 시큐리티가 session을 만들어줍니다.(Security ContextHolder에다가 세션정보를 저장해줌)
// 오브젝트타입 => Authentication 타입 객체가 저장된다.
// Authentication 안에 User 정보가 있어야 됨.
// User 오브젝트타입 => UserDetails 타입 객체여야한다.

// Security Session안에 => Authentication 객체 안에=> UserDetails(PrincipalDetails) 타입이어야한다.

import com.example.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    private Map<String, Object> attributes;

    // 일반로그인할때 하는 생성자
    public PrincipalDetails(User user) {
        this.user=user;
    }
    // OAuth로그인하는 생성자자
   public PrincipalDetails(User user, Map<String,Object> attributes) {
        this.user=user;
        this.attributes=attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect=new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
