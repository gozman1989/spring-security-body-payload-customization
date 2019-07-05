package com.gozman.security.config;

import com.gozman.security.security.AuthentificationProvider;
import com.gozman.security.security.CustomAuthentificationSuccessHandler;
import com.gozman.security.security.RequestPayloadUserNamePasswordAuthentificationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Arrays;


@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthentificationProvider authentificationProvider;



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .antMatchers("/login", "/login-error", "public", "/login2").permitAll()
                .antMatchers("/t1").hasRole("gozman")
                .and()
                .csrf().ignoringAntMatchers("/login2");

        RequestPayloadUserNamePasswordAuthentificationFilter requestPayloadUserNamePasswordAuthentificationFilter
                = new RequestPayloadUserNamePasswordAuthentificationFilter(new AntPathRequestMatcher("/login2", "POST"));



        /*
        * multiple authentification providers can be set
        * the order is important as the first one that is succesfull will define the user roles
        *
         */
        AuthenticationManager authenticationManager = new ProviderManager(Arrays.asList(authentificationProvider));
        requestPayloadUserNamePasswordAuthentificationFilter.setAuthenticationManager(authenticationManager);

        requestPayloadUserNamePasswordAuthentificationFilter.setAuthenticationSuccessHandler(new CustomAuthentificationSuccessHandler());


       /*
       * add our own  custom AuthentificationFilter
        */
        http.addFilterAt(requestPayloadUserNamePasswordAuthentificationFilter, UsernamePasswordAuthenticationFilter.class);

    }



}