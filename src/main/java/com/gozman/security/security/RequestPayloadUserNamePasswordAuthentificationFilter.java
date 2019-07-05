package com.gozman.security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

public class RequestPayloadUserNamePasswordAuthentificationFilter extends AbstractAuthenticationProcessingFilter {

    /*
    * class used to convert json string to pojo
     */
    private ObjectMapper objectMapper = new ObjectMapper();

    /*
    *constructor for defining a url to which this filter gets triggered
    */
    public RequestPayloadUserNamePasswordAuthentificationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    /*
    * constructor for defining a url and optionally a method to which *this filter gets triggered
     */
    public RequestPayloadUserNamePasswordAuthentificationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    /*
    * similar to attemptAuthentication from UsernamePasswordAuthenticationFilter
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        UsernameAndPassword usernameAndPassword = getUserNameAndPAssword(request);
        String username = usernameAndPassword.getUsername();
        String password = usernameAndPassword.getPassword();

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    private UsernameAndPassword getUserNameAndPAssword(HttpServletRequest request) throws IOException {
        String body = request.getReader().lines().collect(Collectors.joining());
        UsernameAndPassword usernameAndPassword = objectMapper.readValue(body, UsernameAndPassword.class);
        return usernameAndPassword;
    }

    protected void setDetails(HttpServletRequest request,
                              UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }
}
