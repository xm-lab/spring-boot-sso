package com.test.login.config;

import java.security.KeyPair;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

/**
 * OAuth2 服务端配置
 * 
 * http://blog.csdn.net/j754379117/article/details/70175198
 * http://www.cnblogs.com/xingxueliao/p/5911292.html
 * http://www.jianshu.com/p/dd1b0983594c
 * 
 * @author tangyz
 *
 */
/* @EnableAuthorizationServer : 启用OAuth2认证服务器功能，当用此注解后，应用启动后将自动生成几个[Endpoint](http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/endpoint/AuthorizationEndpoint.html)
 * /oauth/authorize：验证
 * /oauth/token：获取token
 * /oauth/confirm_access：用户授权
 * /oauth/error：认证失败
 * /oauth/check_token：资源服务器用来校验token
 * /oauth/token_key：如果jwt模式则可以用此来从认证服务器获取公钥
 * 以上这些endpoint都在源码里的endpoint包里面。
 */
@Configuration
@EnableAuthorizationServer
public class OAuthConfigurer extends AuthorizationServerConfigurerAdapter {

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource(
                "keystore.jks"), "tc123456".toCharArray()).getKeyPair("tycoonclient");
        converter.setKeyPair(keyPair);
        return converter;
    }

    /**
     * client的信息的读取：在ClientDetailsServiceConfigurer类里面进行配置，可以有in-memory、jdbc等多种读取方式。
     * jdbc需要调用JdbcClientDetailsService类，此类需要传入相应的DataSource.
     * 
     * authorizedGrantTypes：有四种授权方式 
     * - Authorization Code：用验证获取code，再用code去获取token（用的最多的方式，也是最安全的方式）
     * - Implicit: 隐式授权模式
     * - Client Credentials (用來取得 App Access Token)
     * - Resource Owner Password Credentials
     * 
     * scope：表示权限范围，可选项，用户授权页面时进行选择
     * authorities：授予client的权限
     * 
     * @param clients client客户端的信息配置。client信息包括：clientId、secret、scope、authorizedGrantTypes、authorities
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients)
            throws Exception {
    	// 指定OAuth2的客户端ID为ssoclient，密钥为ssosecret，这将在使用SSO的客户端的配置中用到。
        clients.inMemory().withClient("ssoclient").secret("ssosecret")
                .autoApprove(true) // 自动确认授权，这样登录用户登录后，不再需要进行一次授权确认操作
                .authorizedGrantTypes("authorization_code", "refresh_token").scopes("openid");
    }

    /**
     * 
     * @param security 声明安全约束，哪些允许访问，哪些不允许访问
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security)
            throws Exception {
        security.tokenKeyAccess("permitAll()").checkTokenAccess(
                "isAuthenticated()").allowFormAuthenticationForClients();
    }

    /**
     * @param endpoints 声明授权和token的端点以及token的服务的一些配置信息，比如采用什么存储方式、token的有效期等
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {
        endpoints.accessTokenConverter(jwtAccessTokenConverter());
    }

}
