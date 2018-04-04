package com.imooc.sso.server;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;


/**
 * SSO认证服务器配置
 * @author longxn
 */
@Configuration
@EnableAuthorizationServer
public class SsoAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory()
			.withClient("imooc1")
			.secret("imoocsecret1")
			.authorizedGrantTypes("authorization_code","refresh_token")
			.scopes("all")
			.and()
			.withClient("imooc2")
			.secret("imoocsecret2")
			.authorizedGrantTypes("authorization_code","refresh_token","password")
			.scopes("all")
			.and()
			.withClient("imoocapp")
			.secret("imoocsecretapp")
			.authorizedGrantTypes("refresh_token","password")
			.scopes("all");
		
//		clients.withClient(config.getClientId()).secret(config.getClientSecret())
//		.accessTokenValiditySeconds(config.getAccessTokenValiditySeconds())
//		.refreshTokenValiditySeconds(securityProperties.getOauth2().getRefreshTokenValiditySeconds())
//		.authorizedGrantTypes("refresh_token", "password").scopes("all", "read", "write");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.tokenStore(jwtTokenStore())
				.accessTokenConverter(jwtAccessTokenConverter());
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("isAuthenticated()");//配置一个授权表达式, client能够去认证服务器拿到SigningKey;
	}
	
	/** jwt相关 */
	@Bean
	public TokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		// 设置安全密钥
		accessTokenConverter.setSigningKey("imooc");
		return accessTokenConverter;
	}
}
