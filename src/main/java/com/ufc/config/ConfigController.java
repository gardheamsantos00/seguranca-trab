package com.ufc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class ConfigController extends WebSecurityConfigurerAdapter {

	@Autowired
    private AccessDeniedHandler acessoNegado;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
	        .authorizeRequests()
	        .antMatchers("/", "/home", "/about").permitAll()
	        .antMatchers("/admin/**").hasAnyRole("ADMIN")
	        .antMatchers("/user/**").hasAnyRole("USER")
	        .anyRequest().authenticated()
	        .and()
	        .formLogin()
	        .loginPage("/login")
	        .permitAll()
	        .and()
	        .logout()
	        .permitAll()
	        .and()
	        .exceptionHandling().accessDeniedHandler(acessoNegado);
	}
 
	@Autowired
    public void configGlobal(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("user").password("123").roles("USER")
                .and()
                .withUser("admin").password("123").roles("ADMIN")
                .and()
                .withUser("gardheam").password("123").roles("ADMIN")
                .and()
                .withUser("davi").password("123").roles("USER")
                .and()
                .withUser("test2").password("123").roles("USER")
                .and()
                .withUser("test4").password("123").roles("USER");
    }
	
	
}
