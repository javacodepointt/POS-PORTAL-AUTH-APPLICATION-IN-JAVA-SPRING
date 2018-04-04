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

		http.antMatcher("/**").requestMatchers().antMatchers("/login", "/oauth/authorize", "/auth/rest/hello/upload").and()
				.authorizeRequests().anyRequest()
				.authenticated().antMatchers(HttpMethod.POST, "/auth/rest/hello/upload").hasAuthority("read")
				.and().formLogin().loginPage("/secure.html").loginProcessingUrl("/login").permitAll().and()
				.sessionManagement().maximumSessions(30)
				.expiredUrl("/login?expired");
		
	}

	/*
	 * @Override protected void configure(AuthenticationManagerBuilder auth)
	 * throws Exception {
	 * 
	 * auth.parentAuthenticationManager(authenticationManager)
	 * .inMemoryAuthentication() .withUser("Raviverma") .password("raviverma")
	 * .roles("USER"); }
	 */

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser(env.getProperty("security.user.name"))
				.password(env.getProperty("security.user.password")).roles(env.getProperty("security.user.role"));
		
	}
}
