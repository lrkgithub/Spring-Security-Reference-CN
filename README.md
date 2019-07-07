# Spring-Security-Reference-CN

作者
章节Ⅰ 前言
  1. Spring Security 社区
    1.1 获得帮助
    1.2 成为参与者
    1.3 源码
    1.4 Apache 2 License
    1.5 社交媒体
  2. Spring Security 5.1 中的新东西
    2.1 Servlet 
    2.2 WebFlux
    2.3 集成
  3. 获取Spring Security
    3.1 发布版本
    3.2 使用 Maven
      3.2.1 使用 Maven 部署 Spring Boot
      3.2.2 不使用 Spring Boot 的 Maven 部署
      3.2.3 Maven 源
    3.3 Gradle
      3.3.1 使用 Gradle 部署 Spring Boot
      3.3.2 不使用 Spring Boot 的 Gradle 部署
      3.3.3 Gradle 源
    4 项目模块
    4.1 Core-spring-security-core.jar
    4.2  Remoting - spring-security-remoting.jar
    4.3 Web - spring-security-web.jar
    4.4 Config - spring-security-config.jar
    4.5 LDAP - spring-security-ladp.jar
    4.6 OAuth 2.0 Core - spring-security-oauth2-core.jar
    4.7 OAuth 2.0 Client - spring-security-oauth2-client.jar
    4.8 OAuth 2.0 JOSE - spring-security-oauth2-jose.jar
    4.9 ACL - spring-security-acl.jar
    4.10 CAS - spring-security-cas.jar
    4.11 OpenID - spring-security-openid.jar
    4.12 Test - spring-security-test.jar
  5. 示例程序
    5.1 教程示例
    5.2 联系人
    5.3 LDAP 示例
    5.4 OpenID 示例
    5.5 CAS 示例
    5.6 JAAS 示例
    5.7 Pre-Authentication 示例
章节Ⅱ Servlet 应用
  6. Java 配置
    6.1 Hello Web Security Java Configuration
      6.1.1 AbstractSecurityWebApplicationInitializer
      6.1.2 AbstractSecurityWebApplicationIInitializer 不依赖 Spring 容器
      6.1.3 AbstractSecurityWebApplicationInitializer 与 Spring MVC
    6.2 HttpSecurity
    6.3 Java Configuration 和 表单登录
    6.4 授权请求
    6.5 处理登出
      6.5.1 LogoutHandler
      6.5.2 LogoutSuccessHandler
      6.5.3 更多与登出相关的参考
    6.6 OAuth 2.0 客户端
      6.6.1 ClientRegistration
      6.6.2 ClientRegistrationRepository
      6.6.3 OAuth2AuthorizedClient
      6.6.4 OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService
      6.6.5 RegisteredOAuth2AuthorizedClient
      6.6.6 AuthorizationRequestRepository
      6.6.7 OAuth2AuthorizationRequestResolver
      6.6.8 OAuth2AccessTokenResponseClient
    6.7 OAuth 2.0 Login
      6.7.1 Spring Boot 2.x 示例
    8 架构与实现
    8.1 技术概述
      8.1.1 运行时环境
      8.1.2 核心组件
      8.1.3 Authentication
      8.1.4 在 Web 应用中的认证
      8.1.5 Spring Security 中的访问控制（授权）
      8.1.6 本地化
    8.2 核心服务
      8.2.1 The AuthenticationManager, ProviderManager and AuthenticationProvider
      8.2.2 UserDetailsService 实现
    9 测试
    9.1 测试方法安全性 
      9.1.1 安全测试设置
      9.1.2 @WithMockUser
      9.1.3 @WithAnonymousUser
      9.1.4 @WithUserDetails
      9.1.5 @WithSecurityContext
      9.1.6 Test Meta Annotation
    9.2 Spring MVC Test 集成
      9.2.1 设置 MockMvc 和 Spring Security
      9.2.2 SecurityMockMvcRequestPostProcessors
      9.2.3 SecurityMockMvcRequestBuilders
      9.2.4 SecurityMockMvcREsultMatchers 
  10. Web Application Security
    10.1 The Security Filter Chain
      10.1.1 DelegatingFilterProxy
      10.1.2 FilterChainProxy
      10.1.3 过滤器顺序
      10.1.4 请求匹配和 HttpFireWall
      10.1.5 使用其他基于 Filter 的框架
      10.1.6 高级命名空间配置
    10.2 核心安全过滤器
      10.2.1 FilterSecurityInterceptor
      10.2.2 ExceptionTranslationFilte
      10.2.3 SecurityContextPersistenceFilter
      10.2.4 UsernamePasswordAuthenticationFilter 
    10.3 Servlet API 集成
      10.3.1 Servlet 2.5+ 集成
      10.3.2 Servlet 3+ 继承
      10.3.3 Servlet 3.1+ 集成
    10.4 Basic and Digest Authentication
      10.4.1 BasicAuthenticationFilter
      10.4.2 DigestAuthenticationFilter
    10.5 Remember-Me Authentication
      10.5.1 概览
      10.5.2 简单基于哈希的 token 方式
      10.5.3 Persistent Token Approach
      10.5.4 Remember-Me 接口和实现
    10.6 跨站点请求伪造
      10.6.1 CSRF 攻击
      10.6.2 Synchrogazer Token Pattern
      10.6.3 什么时候使用 CSRF 保护
      10.6.4 使用 Spring Security CSRF 保护
      10.6.5 CSRF 注意事项
      10.6.6 覆盖默认配置
    10.7 CORS
    10.8 Security HTTP Response Headers
      10.8.1 默认的 Security 头部
    10.9 Session Managerment
      10.9.1 SessionManagementFilter
      10.9.2 SessionAuthenticationStrategy
      10.9.3 并发控制
    10.10 匿名认证
      10.10.1 总览
      10.10.3 AuthenticationTrustResolver
    10.11 WebSocket 安全
      10.11.1 WebSocket 配置
      10.11.2 WebSocket 认证
      10.11.3 WebSocket 认证
      10.11.4 强制同源策略
  11. 认证
    11.1 认证架构
      11.1.1 Authorities
      11.1.2 预调用处理
      11.1.3 调用后处理
      11.1.4 分层角色
    11.2 安全对象实现
      11.2.1 AOP Alliance （MethodInvocation） Security Interceptor
      11.2.2 AspectJ（JoinPoint） Security Interceptor
    11.3 基于表达式的访问控制
      11.3.1 总览
      11.3.2 Web 安全表达式
      11.3.3 方法安全表达式
    13 Spring Data 集成
    13.1 Spring Data & Spring Security 配置
    13.2 使用 @Query 的 Security 表达式
