package com.pos.portal.configuration;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableOAuth2Sso
@Configuration
public class Oauth2Configuraton extends WebSecurityConfigurerAdapter{


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.antMatcher("/**")
                .authorizeRequests()
                .antMatchers("/", "/login**","/auth/rest/hello/upload")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .maximumSessions(2)
                .expiredUrl("/login?expired")
                .and()
                .invalidSessionUrl("/login")
                .and()
                .rememberMe().rememberMeParameter("tokenName")
                .tokenValiditySeconds(86400);
                		
    }
}
