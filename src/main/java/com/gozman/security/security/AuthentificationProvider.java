package com.gozman.security.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;


/*
* this is a bean
* we can inject any kind of DAO here to valdiate the
* user credentials against the database
 */
@Component
public class AuthentificationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        /*
        * pasword is not encoded
        */
        if (name.equals("gozman") || name.equals("user")){
            List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
            grantedAuthorityList.add(new SimpleGrantedAuthority(name.toUpperCase()));
            return new UsernamePasswordAuthenticationToken(name, password,  grantedAuthorityList);
        }

        return new UsernamePasswordAuthenticationToken(
                    name, password, new ArrayList<>());

    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
