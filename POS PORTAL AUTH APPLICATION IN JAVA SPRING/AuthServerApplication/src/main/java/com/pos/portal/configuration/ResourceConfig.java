package com.pos.portal.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@EnableResourceServer
@Configuration
@PropertySource("classpath:application.properties")
public class ResourceConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	Environment env;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.requestMatchers()
		                .antMatchers("/login", "/oauth/authorize")
		                .and()
		                .authorizeRequests()
		                .anyRequest()
		                .authenticated()
		                .and()
		                .formLogin()
		                .permitAll();
		
	}

	

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(env.getProperty("security.user.name"))
				.password(env.getProperty("security.user.password")).roles(env.getProperty("security.user.role"));
		
	}
}
