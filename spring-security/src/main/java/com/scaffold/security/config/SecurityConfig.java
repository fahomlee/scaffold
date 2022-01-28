package com.scaffold.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //可配置成从数据库验证 auth.jdbcAuthentication()
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("root")
                .password(new BCryptPasswordEncoder().encode("123456"))
                .authorities(new SimpleGrantedAuthority("roleA"));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //该目录下都可访问
                .antMatchers("/resources/**", "/signup", "/about").permitAll()
                //拥有角色才可访问   "ROLE_ADMIN"
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
                //其他请求都要认证
                .anyRequest().authenticated()
                .mvcMatchers("/index/**").hasRole("rolB")
                .and()
                //登录 可指定登录页
                .formLogin()
                .and()
                //登出 可指定跳转页
                .logout()
                .and()
                //记住我
                .rememberMe()
                .and()
                .httpBasic();
    }
}
