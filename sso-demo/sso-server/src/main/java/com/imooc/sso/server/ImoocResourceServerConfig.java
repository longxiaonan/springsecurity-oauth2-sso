package com.imooc.sso.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * 通过注解@EnableResourceServer开启了一个资源服务器, demo项目是继承了这个项目, demo项目就是一个授权服务器了
 * @author longxn
 *
 */
@Configuration
@EnableResourceServer
public class ImoocResourceServerConfig extends ResourceServerConfigurerAdapter{
	
	@Autowired
	private AuthenticationSuccessHandler imoocAuthenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler imoocAuthenticationFailureHandler;
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.formLogin()//登录方式:表单
			.loginPage("/authentication/require")//指定登录页面
			.loginProcessingUrl("/authentication/form")//登录请求地址, 告诉UsernamePasswordAuthenticationFilter的登录请求地址, 该filter默认的登录地址是/login
			.successHandler(imoocAuthenticationSuccessHandler)
			.failureHandler(imoocAuthenticationFailureHandler)
//		http.httpBasic()//登录方式:基本
			.and()
			.authorizeRequests()//进行授权
			.antMatchers("/authentication/require").permitAll() //放通登录页面, 否则不停的跳到登录页面会导致请求过多
			.anyRequest()//任何请求
			.authenticated()//都需要认证
			.and()
			.csrf().disable();//暂时关闭csrf
		
	}
	
}
