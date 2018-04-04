package com.imooc.sso.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** 使sso生效 */

@SpringBootApplication
@RestController
@EnableOAuth2Sso
public class SsoClient1Application {

	/** 获取jwt中的用户, 通过authentication返回, 用于登录后返回用户登录的信息 */
	@GetMapping("/user")
	public Authentication user(Authentication user){
		return user;
	}
	
	public static void main(String[] args) {
		SpringApplication.run(SsoClient1Application.class, args);
	}
}
