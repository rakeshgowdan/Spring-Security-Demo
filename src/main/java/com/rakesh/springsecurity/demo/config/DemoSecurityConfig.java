package com.rakesh.springsecurity.demo.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;




@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		UserBuilder users=User.withDefaultPasswordEncoder();
		auth.inMemoryAuthentication()
		.withUser(users.username("rakesh").password("1234").roles("Employee","ADMIN"))
		.withUser(users.username("Manager").password("1234").roles("Employee","Manager"))
		.withUser(users.username("Employee").password("1234").roles("Employee"));
		
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/").hasRole("Employee")
		.antMatchers("/leaders/**").hasRole("Manager")
		.antMatchers("/sysadmin/**").hasRole("ADMIN")
		.and().formLogin().loginPage("/showLoginPage")
		.loginProcessingUrl("/authenticateTheUser")
		.permitAll()
		.and()
		.logout().permitAll()
		.and()
		.exceptionHandling()
		.accessDeniedPage("/access-denied")
		;
	}

	
	
}
