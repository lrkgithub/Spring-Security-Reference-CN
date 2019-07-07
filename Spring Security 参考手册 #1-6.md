# Spring Security 参考手册

## 作者

Ben Alex , Luke Taylor , Rob Winch , Gunnar Hillert , Joe Grandja , Jay Bryant



5.2.0.BUILD-SNAPSHOT



版权所有©2004-2017

本文件的副本可供您自己使用和分发给他人，前提是您不对此类副本收取任何费用，并且每份副本均包含本版权声明，无论是以印刷版还是电子版分发。

Spring Security 是一个提供认证，授权和保护常用攻击的框架。Spring Security是一个事实上的基于Spring框架的安全层应用，对命令式和反应式应用都有一流的支持。



[TOC]





## 章节Ⅰ 前言

这一部分将会讨论 Spring Security 的流程。



### 1. Spring Security 社区

欢迎来到 Spring Security 社区！这章节将会讨论如何利用我们庞大社区的价值。



#### 1.1 获得帮助

如果你需要有关于 Spring Security 的帮助,我们这里将提供帮助。下面是获取帮助的一些最好的方式

- 阅读我们的参考手册
- 使用一下我们众多的例子
- 在 [https://stackoverflow.com](https://stackoverflow.com/) 网站上，带上 `spring-security` 标签进行提问
- 在 <https://github.com/spring-projects/spring-security/issues> 上报告 Bug 和提出请求。



#### 1.2 成为参与者

我们欢迎你参与到 Spring Security 项目中来。为 Spring Security 贡献的方式有很多种，包括 在 StackOverflow 网站上回答问题，编写新的代码，提升已有代码，完善文档，提供更多例子和教程，或者简单的提出建议。




#### 1.3 源码

Spring Security 的源码可以在 <https://github.com/spring-project/spring-security> 上找到。



#### 1.4 Apache 2 License

Spring Security 是一个开源软件，遵循 Apache 2.0 license



#### 1.5 社交媒体

你可以在 Twitter 关注 `@SpringSecurity` 和 `Spring Security Team` 及时了解最新的信息。你可以关注 `@SpringCentral` 以获取 Spring 全部框架的信息。




### 2. Spring Security 5.1 中的新东西

Spring Security 5.1 提供了许多新的特性。以下是这次发布的亮点。



#### 2.1 Servlet 

* 通过 UserDetailsPasswordService 自动存储密码升级
* OAuth 2.0 Client
  * 定制化认证和令牌请求
  * 支持 `authorization_code`  （授权码认证）
  * 支持 `client_credentials` （ Client 模式）
* OAuth 2.0 资源服务器 - 支持 JWT-encoded bearer 令牌
* 增加 OAuth2 WebClient 集成
* HTTP Firewall 保护 HTTP 动词篡改 ( HTTP Verb Tampering ) 和 跨域攻击
* ExceptionTranslationFilter 支持通过 RequestMatcher 来选择 AccessDeniedHandler 
* CSRF 支持排除某些特定的请求
* 增加对 Feature Policy 的支持
* 增加 @Transient 认证令牌
* 默认登陆页面的现代外观（lock-and-feel）



#### 2.2 WebFlux

* 通过 ReactiveUserDetailsPasswordService 自动存储密码升级
* 增加 OAuth2 支持
  * 增加 OAuth2 客户端支持
  * 增加 OAuth2 资源服务器支持
  * 增加 OAuth2 WenClient 集成
* `@WithUserDetails` 现在可以与 `ReactiveUserDetailsService` 一起工作
* 增加 CROS 支持
* 增加一下的 HTTP 头支持
  * Content Security Policy
  * Feature Policy
  * Referrer Policy
* 重定向至 HTTPS 
* 提升 @AuthenticationPrincipal
  * 支持解析 beans
  * 支持解析 errorOnInvalidType



#### 2.3 集成

* Jackson Support 与 `BadCredentialsException` 
* 在测试阶段，设置 `SecurityContext` 时，支持自定义 `@WithMockUser` 。举例来说， `@WithMockUser（setupBefore = TestExecutionEvent.TEST_EXECUTION）`将会在测试执行之前，JUnit的 `@Before` 注解之后，设定一个使用者
* LDAP 认证可以在自定义环境参数中设置
* X.509 认证支持委托策略



### 3. 获取Spring Security

这一节讨论你需要知道的关于获取 Spring Security 二进制文件（编译好的版本）的全部知识。请参考 [1.3 节 “源码”](https://github.com/lrkgithub/Spring-Security-Reference-CN/issues/1#community-source)，了解如何获取源码。



#### 3.1 发布版本

Spring Security 版本是以 MAJOR、MINOR、PATCH， 例如：

- MAJOR 版本可能包含突破性进展。通常是提供更好的安全技术来适应当前的安全策略。
- MINOR 版本包含功能更新，可以视作被动更新
- PATCH 级别除了修复可能的bug之外，应该是完全向前向后兼容的



#### 3.2 使用 Maven

像大多数开源的项目，Spring Security 将它的依赖作为 Maven 的项目（artifact）来部署。接下来的章节提供了如何使用 Maven 来配置 Spring Security 的细节。



##### 3.2.1 使用 Maven 部署 Spring Boot

Spring Boot 提供了聚集了 Spring Security 相关依赖的 spring-boot-starter-security 启动器。最简单和建议的方式是在使用 IDE 中集成的或者通过 [http://start.spring.io](http://start.spring.io/) 来使用 Spring Initializer。

当然，也可以手动的添加启动器。

pom.xml

```
<dependencies>
    <!-- ... other dependency elements ... -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
</dependencies>
```

因为 Spring Boot 提供了 Maven Boom 来管理依赖版本，所以没有必要加上版本号。如果你希望重写 Spring Security 的版本号，你可以使用一个 Maven 的参数来完成：

pom.xml

```
<properties>
    <!-- ... -->
    <spring-security.version>5.2.0.BUILD-SNAPSHOT</spring-security.version>
</dependencies>
```

因为 Spring Security 只在 major 版本中提供突破性进展，所以使用一个最新版本的带 Spring Security 的 Spring Boot 是比较安全的。当然，有时升级 Spring Framework 版本也是必要的。这也可以简单地通过添加一个 Maven 参数来完成：

pom.xml

```
<properties>
    <!-- ... -->
    <spring.version>5.2.0.M2</spring.version>
</dependencies>
```

如果你想添加额外的功能，例如 LDAP，OpenID之类的。你需要适当的引入 [4节 “项目模块”](https://github.com/lrkgithub/Spring-Security-Reference-CN/issues/1#community-source) 的内容。



##### 3.2.2 不使用 Spring Boot 的 Maven 部署

如果部署 Spring Security 却不部署 Spring Boot，推荐的方式是利用 Spring Security 的 BOM 来确定整个项目中的 Spring Security 版本一致。

pom.xml

```
<dependencyManagement>
    <dependencies>
        <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-bom</artifactId>
            <version>5.2.0.BUILD-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

一个最小的 Spring Security Maven 依赖集合通常类似于如下：

pom.xml

```
<dependencies>
    <!-- ... other dependency elements ... -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-config</artifactId>
    </dependency>
</dependencies>
```

如果你想添加额外的功能，例如 LDAP，OpenID之类的。你需要适当的引入 [4节 “项目模块”](https://github.com/lrkgithub/Spring-Security-Reference-CN/issues/1#community-source) 的内容。

Spring Security 是基于 Spring Framework 5.2.0.M2 版本来构建的，但是通常可以与任意更新版本的 Spring Framework 5.x 一起工作。许多使用者困扰的问题是， Spring Security 的传递依赖是 Spring Framework 5.2.0.M2版本，这可能会导致奇怪的类路径（classpath）问题。最简单的解决方式是在你的 pom.xml 中，加入 `spring-framework-bom` 到 `<dependencyManagement>` 部分，如下所示：

pom.xml

```
<dependencyManagement>
    <dependencies>
        <!-- ... other dependency elements ... -->
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-framework-bom</artifactId>
            <version>5.2.0.M2</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

这样可以确保 Spring Security 所有的传递依赖使用了 Spring 5.2.0.M2 模块。



##### 3.2.3 Maven 源

pom.xml

```
<repositories>
    <!-- ... possibly other repository elements ... -->
    <repository>
        <id>spring-snapshot</id>
        <name>Spring Snapshot Repository</name>
        <url>https://repo.spring.io/snapshot</url>
    </repository>
</repositories>
```

如果你选用了 milestone 或者 发布的候选版本，你需要确保你有 Spring Milestone 源，如下所示：

pom.xml

```
<repositories>
    <!-- ... possibly other repository elements ... -->
    <repository>
        <id>spring-milestone</id>
        <name>Spring Milestone Repository</name>
        <url>https://repo.spring.io/milestone</url>
    </repository>
</repositories>
```



#### 3.3 Gradle

像大多数开源项目， Spring Security 以 Maven 方式部署它的依赖，这样可以获得一流的 Gradle 支持。接下来的章节，会提供如何使用 Gradle 配置 Spring Security 的细节。



##### 3.3.1 使用 Gradle 部署 Spring Boot

Spring Boot 提供了聚集了 Spring Security 相关依赖的 spring-boot-starter-security 启动器。最简单和建议的方式是在使用 IDE 中集成的或者通过 [http://start.spring.io](http://start.spring.io/) 来使用 Spring Initializer。

当然，也可以手动增加依赖：

build.gradle

```
dependencies {
    compile "org.springframework.boot:spring-boot-starter-security"
}
```

因为 Spring Boot 提供了一个 Maven BOM 来管理版本，这里就没有必要再精确到版本号。如果你希望重写 Spring Security 的版本，你也可以通过一个 Gradle 参数来这样做：

build.gradle

```
ext['spring-security.version']='5.2.0.BUILD-SNAPSHOT'
```

因为 Spring Security 只在 major 版本中提供突破性修改，所以使用最新的带 Spring Security 的 Spring Boot 版本是更安全的。当然，有时升级 Spring Framework 版本也是必要的。这也可以简单地通过添加一个 Gradle 参数来完成：

build.gradle

```
ext['spring.version']='5.2.0.M2'
```

如果你想添加额外的功能，例如 LDAP，OpenID之类的。你需要适当的引入 [4节 “项目模块”](https://github.com/lrkgithub/Spring-Security-Reference-CN/issues/1#community-source) 的内容。



##### 3.3.2 不使用 Spring Boot 的 Gradle 部署

如果部署 Spring Security 却不部署 Spring Boot，推荐的方式是利用 Spring Security 的 BOM 来确定整个项目中的 Spring Security 版本一致。这可以利用 Dependency Management Plugin 来完成

build.gradle

```
plugins {
    id "io.spring.dependency-management" version "1.0.6.RELEASE"
}

dependencyManagement {
    imports {
        mavenBom 'org.springframework.security:spring-security-bom:5.2.0.BUILD-SNAPSHOT'
    }
}
```

一个最小的 Spring Security Maven 依赖集合通常类似于如下：

**build.gradle**

```
dependencies {
    compile "org.springframework.security:spring-security-web"
    compile "org.springframework.security:spring-security-config"
}
```

如果你想添加额外的功能，例如 LDAP，OpenID之类的。你需要适当的引入 [4节 “项目模块”](https://github.com/lrkgithub/Spring-Security-Reference-CN/issues/1#community-source) 的内容。

Spring Security 是基于 Spring Framework 5.2.0.M2 版本来构建的，但是通常可以与任意更新版本的 Spring Framework 5.x 一起工作。许多使用者困扰的问题是， Spring Security 的传递依赖是 Spring Framework 5.2.0.M2版本，这可能会导致奇怪的类路径（classpath）问题。最简单的解决方式是在你的 pom.xml 中，加入 `spring-framework-bom` 到 `<dependencyManagement>` 部分，如下所示：（这可以使用 Dependency Management Plugin 来完成）

**build.gradle**

```
plugins {
    id "io.spring.dependency-management" version "1.0.6.RELEASE"
}

dependencyManagement {
    imports {
        mavenBom 'org.springframework:spring-framework-bom:5.2.0.M2'
    }
}
```

这样可以确保 Spring Security 所有的传递依赖使用了 Spring 5.2.0.M2 模块。

##### 3.3.3 Gradle 源

所有 GA 版本（以 .RELEASE 结尾的版本号）都部署在 Maven 中心中，所以使用 mavenCentral() 源来获取 GA 版本就足够了。

**build.gradle**

```
repositories {
    mavenCentral()
}
```

如果你想使用一个 SNAPSHOT 版本，你需要确保你将 Spring Snapshot 源像如下所示定义正确

**build.gradle**

```
repositories {
    maven { url 'https://repo.spring.io/snapshot' }
}
```

如果你想使用 milestone 或者发布的候选版本，你需要确保你将 Spring milestone 源像如下定义正确

**build.gradle**

```
repositories {
    maven { url 'https://repo.spring.io/milestone' }
}
```



### 4 项目模块

在 Spring Security 3.0 中，代码库已经被分为几个独立的 jar 包，这样可以更清晰的区分功能和第三方 jar 包依赖。如果你是用 Maven 来构建你的项目，那么这里有几个模块需要你加入到你的 `pom.xml` 中。即使你不使用 Maven ，我们仍建议你的参考这个 `pom.xml` 来了解第三方依赖以及版本。另外，检查示例程序包含的库是一个好主意。



#### 4.1 Core-spring-security-core.jar

包含核心认证和访问控制的类和接口，远程支持和基础的配置 API 。任何使用 Spring Security 的程序都需要。支持独立应用，远程客户，方法（服务层）安全以及 JDBC 用户配置。包含如下的顶级包：

- `org.springframework.security.core`
- `org.springframework.security.access`
- `org.springframework.security.authentication`
- `org.springframework.security.provisioning`



#### 4.2  Remoting - spring-security-remoting.jar

提供与 Spring Remote 的集成。如果你不是在写一个使用 Spring Remoting 的客户端的话，并不需要使用这个模块。主要的 package 是：

* `org.springframework.security.remoting`



#### 4.3 Web - spring-security-web.jar

包含过滤器和 web 安全相关的基础代码。所有基于 servlet API 的依赖。如果你使用 Spring Security Web 安全认证服务和基于 URL 的认证控制。主要的package是：

* `org.springframework.security.web`



#### 4.4 Config - spring-security-config.jar

包含安全命名空间解析代码和 Java 配置代码。如果你使用 Spring Security XML 命名空间作为配置或者使用 Spring Security 的 Java 配置作为支持，那么你需要这个 jar 。这里主要的 package 是 `org.springfranework.security.config` 。这个包里的类并不希望被在项目中被直接使用。



#### 4.5 LDAP - spring-security-ladp.jar

LDAP 认证和配置代码。如果你希望使用 LDAP 认证或控制 LDAP 用户条目。这里的顶级 package 是：`org.springframework.security.ldap`。



#### 4.6 OAuth 2.0 Core - spring-security-oauth2-core.jar

`spriong-security-oauth2-core.jar` 包含了提供支持 OAuth 2.0 框架和 OpenID Connect Core 1.0 的核心类和接口。当应用基于 OAuth 2.0 或者 OpenID Connection Core 1.0 来架构，例如，客户端，资源服务器，认证服务器等的时候，需要使用这个 jar 包。这个顶级 package 是： `org.springframework.security.oauth2.core`。



#### 4.7 OAuth 2.0 Client - spring-security-oauth2-client.jar

`spring-security-oauth2-client.jar` 是 Spring Security 提供给客户端来支持 OAuth 2.0 认证框架和 OpenID Connect Core。当应用需要利用 OAuth 2.0 登录和/或 OAuth 客户端支持，这个 jar 是必须的。顶级的 package 是 `org.springframework.security.oauth2.client`。



#### 4.8 OAuth 2.0 JOSE - spring-security-oauth2-jose.jar

`spring-security-oauth2-jose.jar` 包含 Spring Security 对 JOSE（JavaScript Object Signing and Encryption） 框架的支持。JOSE 框架的目的是在更方之间，安全的传递认证。它建立在一系列的规范之上：

* JSON Web Token（JWT）
* JSON Web Signature（JWS）
* JSON Web Encryption（JWE）
* JSON Web Key（JWK）

它包含的顶级 package 有：

* `org.springframework.security.oauth2.jwt`
* `org.springframework.security.oaut2.jose`



#### 4.9 ACL - spring-security-acl.jar

特定的域对象 ACL 实现。用来在你的应用中，对特定的域对象应用安全策略。顶级 package 是： `org.springframework.security.acls` 。



#### 4.10 CAS - spring-security-cas.jar

Spring Security 的 CAS 客户端集成。如果你希望把 Spring Security web 认证和 CAS 单点登录服务器一起使用。顶级 package 是：`org.springframework.security.cas` 。



#### 4.11 OpenID - spring-security-openid.jar

OpenID web 认证支持。用来认证使用者对应一个外部 OpenID 服务器。顶级 package 是 `org.springframework.security.openid` 。需要 OpenID4Java 。



#### 4.12 Test - spring-security-test.jar

支持 Spring Security 的测试。



### 5. 示例程序

在源代码中包含了一些[示例程序](https://github.com/spring-projects/spring-security/tree/master/samples/xml)。你可以在 samples/xml 的子文件夹地下找到。

本章提到的所有路径都与项目源码目录对应。



#### 5.1 教程示例

这个教程示例是一个不错的基础示例，帮助你开始学习。它通篇使用命名空间配置。编译后的应用包含在发布的 zip 文件中，方便部署在你的 web 容器中（spring-security-samples-tutorial-3.1.x.war）。基于表单的认证和通常使用的 remember-me 认证一起使用，以使用cookies自动记住登录。

我们建议你从教程示例开始，因为 XML 比较简单，容易学习。最重要的是，你可以简单地将这个 XML 文件（以及相关的 web.xml 项目）加入到你的已有项目中。只有当基础的集成完成之后，我们才建议你尝试着增加方法授权或者领域对象安全。



#### 5.2 联系人

这个 Contacts Sample 是一个高级示例，它有着比基础应用安全之外的，强大的领域对象访问控制列表功能 （ACLs） 。这个示例提供了一个接口，用户可以通过这个接口来控制一个简单的联系人数据库（领域对象）。

为了部署，简答地从 Spring Security 发布项目中拷贝 WAR 文件到你的容器的 `webapps` 目录。这个 war 应该被命名为 `spring-security-samples-contacts-3.1.x.war` （后面的 x 版本号根据使用的版本会有所不同）。

在启动你的容器之后，检查你应用是否加载。访问 http://localhost:8080/contacts （或者其他 URL 适用你的 web 容器和你部署的 WAR）。

接下来，点击 “DEBUG”。你就会被提示需要进行身份验证，一系列建议的用户名和密码在这个页面上。使用其中的一对进行简单地认证，然后查看结果页面。它应该包含认证成功的信息，类似于如下：

```Spring Boot
Security Debug Information

Authentication object is of type:
org.springframework.security.authentication.UsernamePasswordAuthenticationToken

Authentication object as a String:

org.springframework.security.authentication.UsernamePasswordAuthenticationToken@1f127853:
Principal: org.springframework.security.core.userdetails.User@b07ed00: Username: rod; \
Password: [PROTECTED]; Enabled: true; AccountNonExpired: true;
credentialsNonExpired: true; AccountNonLocked: true; \
Granted Authorities: ROLE_SUPERVISOR, ROLE_USER; \
Password: [PROTECTED]; Authenticated: true; \
Details: org.springframework.security.web.authentication.WebAuthenticationDetails@0: \
RemoteIpAddress: 127.0.0.1; SessionId: 8fkp8t83ohar; \
Granted Authorities: ROLE_SUPERVISOR, ROLE_USER

Authentication object holds the following granted authorities:

ROLE_SUPERVISOR (getAuthority(): ROLE_SUPERVISOR)
ROLE_USER (getAuthority(): ROLE_USER)

Success! Your web filters appear to be properly configured!
```

一旦你成功地收到以上信息，回到示例程序的主页面，并点击 “Manage” 按钮。然后你可以试用一下这个应用。请注意，对当前登录用户唯一可见的联系人信息已经显示，并且，只有 `ROLE_SUPERVISOR` 的用户有权限去删除他们的联系人。在这个场景背后，是 `MethodSecurityInterceptor` 在保护业务对象。

这个应用允许你去修改不同联系人的访问控制列表。确保尝试一下，并且通过回顾应用上下文的 XML 文件来理解它是怎么工作的。



#### 5.3 LDAP 示例

LDAP 示例程序提供了基础的配置，并且在同一份应用上下文文件中，使用两种配置方式，一种是命名空间配置方式，另一种是相同配置的传统 bean 配置方式。这意味着这个应用里实际有两份相同的认证提供者配置。



#### 5.4 OpenID 示例

OpenID示例演示了怎样使用命名空间来配置OpenID，怎样为 Google， Yahoo 和 MyOpenID 认证提供者设置 attribute exchange 配置（也可以尝试其他的提供者，如果你喜欢的话）。这个示例使用了基于 JQuery 的 openid-selector 项目来提供使用者友好型登录页面，这允许使用者简单的选择一个提供者，而不是输出全部的 OpenID 认证。

这个应用与众不同的地方是，它允许任何用户访问站点（只要通过身份认证）。第一次你登录，你会得到一个 "Welcome [your name]" 信息。如果你登出有登录（使用相同的身份认证），那么它会显示 "Welcome Back" 。这是通过 `UserDetailsService` 来完成的，给每一个用户分配一个标准角色并存储在内部的 map 中。显然，一个真正的应用应该使用一个数据库来替代。通过阅读源码可以获取更多的信息。这个类好考虑了如下情况，不同的提供者返回不同的属性信息，并构建指向相应用户的名称。



#### 5.5 CAS 示例

这个 CAS 示例程序需要你一起运行 CAS 服务端和 CAS 客户端。这不包含在发布的内容中，所以你应该查看项目介绍中描述的项目代码。在 `samples/cas` 目录下，你可以找到相关文件。这里还有一个 `Readme.txt` 文件，解释了如何直接从代码树里，一起运行服务端和客户端，带着 SSL 支持。



#### 5.6 JAAS 示例

JAAS 示例程序是个十分简单的程序，展示了如何在 Spring Security 中使用 JAAS LoginModule。如果用户名和密码验证通过， LoginModule 会成功认证一个用户，否则，就会抛出 LoginException 异常。这个项目中使用的 AuthorityGranter 总是赋予用户 ROLE_USER 角色。这个示例程序还演示了如何通过设置 jaas-api-provision 为 true ，将 LoginModule 返回的 JAAS Subject 作为主题运行。



#### 5.7 Pre-Authentication 示例

这个示例程序展示了如何把 pre-authentication 框架中的 beans 连接起来，以使用 Java EE 容器中的登录信息。用户的名字和角色是容器设置的。

代码在 `samples/preauth`。





##  章节Ⅱ Servlet 应用



### 6. Java 配置

对 Java Configuration 的基础支持在 Sprng 3.1 版本中就被加入到了 Spring Framework 中。从 Spring Security 3.2 开始， Spring Security 就支持 Java Configuration 使用户可以脱离任何 XML 来简单地配置 Spring Security。

如果你对 <a href="#community-source" title="1.3-源码">7 节，安全命名空间配置</a> 熟悉的话，你应该能找到不少它和 Security Java Configuration 支持之间的共通性。

> Spring Security 提供了不少示例来说明如何使用 Spring Security Java Configuration



#### 6.1 Hello Web Security Java Configuration

第一步是创建我们的 Spring Security Java Configuration 。这个配置创建了一个 Servlet Filter ，就是众所周知的 `springSecurityFilterChain` ，它会对应用中的所有安全（保护应用 URLs，验证提交的用户名和密码，重定向 到登录表单）负责。在下面，你可以找到最基本的 Spring Security Java Configuration ：

```Java
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;

@EnableWebSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

    @Bean
    public UserDetailsService userDetailsService() throws Exception {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
        return manager;
    }
}
```

这确实不是很多配置，但它的作用却很大。你可以在下面找到一个功能摘要：

* 对你的应用中的所有 URL 都需要认证
* 为你生成一个登录表单
* 允许用户使用 用户名“user” 和 密码“password” 基于表单进行身份验证
* 允许用户登出
* 预防 CSRF 攻击
* 保护 Session Fixation
* Security Header 集成
  * HTTP Strict Transport Security 对应安全请求
  * X-Content-Type-Options 集成
  * 缓存控制（在后面可以被你的应用重写，比如允许缓存静态资源）
  * X-XSS-Protection 集成
  * X-Frame-Options 集成来预防 ClickJacking
* 和以下的 Servlet API 进行集成
  - [HttpServletRequest#getRemoteUser()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getRemoteUser())
  - [HttpServletRequest#getUserPrincipal()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getUserPrincipal())
  - [HttpServletRequest#isUserInRole(java.lang.String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#isUserInRole(java.lang.String))
  - [HttpServletRequest#login(java.lang.String, java.lang.String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#login(java.lang.String, java.lang.String))
  - [HttpServletRequest#logout()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#logout())



##### 6.1.1 AbstractSecurityWebApplicationInitializer

下一步是使用 war 来注册 `springSecurityFilterChain` 。这在 Servlet 3.0+ 环境中，可以基于 Spring's WebApplicationInitializer support 用 Java Configuration 来完成。

- [Section 6.1.2, “AbstractSecurityWebApplicationInitializer without Existing Spring”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#abstractsecuritywebapplicationinitializer-without-existing-spring) - 如果你没有使用 Spring ，使用这些配置
- [Section 6.1.3, “AbstractSecurityWebApplicationInitializer with Spring MVC”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#abstractsecuritywebapplicationinitializer-with-spring-mvc) - 如果你已经使用 Spring，使用这些配置



##### 6.1.2 AbstractSecurityWebApplicationIInitializer 不依赖 Spring 容器

如果你没有使用 Spring or Spring MVC ，你就需要传入 `wenSecurityConfig` 到超类中，确保配置被获取。如下所示：

```java
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

    public SecurityWebApplicationInitializer() {
        super(WebSecurityConfig.class);
    }
}
```

`SecurityWebApplicationInitializer` 会做以下的事情：

* 自动为你的应用的每一个 URL 注册 springSecurityFilterChain Filter
* 增加一个 ContextLoaderListener 来加载 WebSecurityConfig



##### 6.1.3 AbstractSecurityWebApplicationInitializer 与 Spring MVC

如果我们在应用的其他地方使用了 Spring ，那么大概已经有了一个用来加载 Spring Configuration 的 `WebApplicationInitializer` 。如果我们使用之前的配置，会得到一个 error。反之，我们应该将 Spring Security 注册到已有的 `ApplicationContext` 中。举例来说，如果我们使用 Spring MVC 或我们的 `SecurityWebApplicationInitializer` ，看上去会是这样：

```java
import org.springframework.security.web.context.*;

public class SecurityWebApplicationInitializer
    extends AbstractSecurityWebApplicationInitializer {

}
```

这会简单地为你的应用的每一个 URL 注册一个 springSecurityFilterChain Filter 。之后，我们需要确保 `webSecurityConfig` 被已经存在的 ApplicationInitializer 加载。举例来说，如果我们使用 Spring MVC ，这应该被加入到 `getRootConfigClass()`：

```java
public class MvcWebApplicationInitializer extends
        AbstractAnnotationConfigDispatcherServletInitializer {

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class[] { WebSecurityConfig.class };
    }

    // ... other overrides ...
}
```



#### 6.2 HttpSecurity

至此，我们的 WebSecurityConfig 只包含关于认证用户的相关信息。Spring Seucrity 怎么知道我们希望所有用户都被认证呢？ Spring Security 怎么知道我们希望支持基于表单的认证？这是因为 `WebSecurityConfiguraerAdapter` 提供了一个默认配置，在 `cofigure(HttpSecurity http)` 方法中：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .anyRequest().authenticated()
            .and()
        .formLogin()
            .and()
        .httpBasic();
}
```

默认配置有如下内容：

* 确保每一个对我们应用的请求，都要求用户被认证
* 允许用户基于表单进行登录
* 允许用户使用 HTTP Basic 进行认证

你会注意到这和 XML 命名空间的配置很相似：

```XML
<http>
    <intercept-url pattern="/**" access="authenticated"/>
    <form-login />
    <http-basic />
</http>
```

Java Configuration 使用 `and()` 来表示和 XML 关闭标志（<.../>）一样的作用，允许用户继续配置父类。如果你阅读代码的话，它也表达同样的意思。我希望配置认证请求，配置基于表单登录，配置 HTTP Basic 认证。



#### 6.3 Java Configuration 和 表单登录

你可能想知道表单登录来自哪里，因为目前为止我们没有在任何的 HTML 文件或者 JSPs 里提到。因为 Spring Security 的默认配置没有明确地设置一个 URL 用作登录页面， Spring Security 自动生成了这一页面，基于使能的特性并且使用标准的 URL 值来处理提交的登录，用户会在登陆之后发送给默认的 URL，以及后续操作。 

虽然自动生成的登录页面在启动时十分方便，运行起来也很快，但是绝大多数应用希望提供自己的登录页面。为了达到这个目的，我们可以更新我们的配置，如下所示：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
            .anyRequest().authenticated()
            .and()
        .formLogin()
            .loginPage("/login") 
            .permitAll();        
}
```

* 这个更新后的配置，明确了登录页面
* 我们必须保证所有用户都可以访问登录页面。`formLogin().permitAll()` 方法授予与基于表单登录页面相关的所有 URL ，全部用户都有访问权。

下面是一个用 JSP 实现的当前的配置的示例：

> 下面是一个我们当前配置的登录页面。如果这些默认配置不符合我们的需求，可以简单地更新这些配置

```JSP
<c:url value="/login" var="loginUrl"/>
<form action="${loginUrl}" method="post">       
    <c:if test="${param.error != null}">        
        <p>
            Invalid username and password.
        </p>
    </c:if>
    <c:if test="${param.logout != null}">       
        <p>
            You have been logged out.
        </p>
    </c:if>
    <p>
        <label for="username">Username</label>
        <input type="text" id="username" name="username"/>  
    </p>
    <p>
        <label for="password">Password</label>
        <input type="password" id="password" name="password"/>  
    </p>
    <input type="hidden"                        
        name="${_csrf.parameterName}"
        value="${_csrf.token}"/>
    <button type="submit" class="btn">Log in</button>
</form>
```

* 一个 POST 请求到达 /login URL 地址时，会触发认证用户
* 如果 query 参数 error 存在，那么意味着认证被触发了并且失败
* 如果 query 参数 logout 存在，那么意味着用户成功地登出了
* 用户名必须使用 HTTP 参数 username 传入
* 密码必须使用 HTTP 参数 password 传入
* 必须理解 [包含 CSRF令牌]() 一节。了解更多，可以阅读 [10.6节，跨站点伪造请求（CSRF）]()。



#### 6.4 授权请求

我们的示例仅仅针对我们应用的每一个 URL ，都要求用户进行认证。我们可以通过在 `http.authorizeRequests()` 方法下增加多个子配置，来指定自定义需求。举例来说：

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()                                                                
            .antMatchers("/resources/**", "/signup", "/about").permitAll()                  
            .antMatchers("/admin/**").hasRole("ADMIN")                                      
            .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")            
            .anyRequest().authenticated()                                                   
            .and()
        // ...
        .formLogin();
}
```

* `http.authorizeRequests()` 下的多个子配置是按配置的顺序进行处理的
* 我们指定多个用户可以直接访问的 URL 匹配模式。特别的，用户可以直接请求，如果目标 URL 是以 “/resources”，等于 "/singup" ，或者等于 "/about"
* 任何以 "/admin" 开头的 URL 地址，都要求用户拥有 “ROLE_ADMIN” 身份。你会注意到，这里不需要增加 "ROLE_" 前缀，因为我们调用了 hasRole 方法
* 任何以 “/db” 开头的 URL 地址，都要求用户同时拥有 "ROLE_ADMIN" 和 "ROLE_DBA" 身份。你会注意到，这里也不需要增加 "ROLE_" 前缀，因为我们调用了 hasRole 方法
* 任何没有被匹配到的 URL 。仅仅需要用户被认证



#### 6.5 处理登出

当使用 `WebSecurityConfigurerAdapter` 时，登出功能是自动增加的。默认下，请求 URL `/logout` 将用户登出，步骤如下：

* 使 HTTP Session 无效
* 清理全部配置的 RememberMe 认证
* 清除 `SecurityContextHolder`
* 重定向到 `/login?logout`

然后，和配置登录功能类似，你也有许多选择来更细化配置登出需求

```java
protected void configure(HttpSecurity http) throws Exception {
    http
        .logout()                                                                
            .logoutUrl("/my/logout")                                                 
            .logoutSuccessUrl("/my/index")                                           
            .logoutSuccessHandler(logoutSuccessHandler)                              
            .invalidateHttpSession(true)                                             
            .addLogoutHandler(logoutHandler)                                         
            .deleteCookies(cookieNamesToClear)                                       
            .and()
        ...
}
```

* 提供登出功能支持。当使用 `WebSecurityConfigurerAdapter` 时，这是自动提供的。
* 触发登出的 URL （默认是 /logout）。如果 CSRF 保护使能了（默认是使能的），那么请求还必须是一个 POST 方法。更多信息，请查看 JavaDoc。
* 登出发生后重定向到的 URL 地址。默认是 /login?logout 。更多信息，请查看 JavaDoc。
* 指定一个自定义的 LogoutSuccessHandler 。如果这被指定了，那么 logoutSuccessUrl() 方法会被忽略。更多信息，请查看 JavaDoc。
* 指定登出时， HttpSession 是否需要失效。默认是设置为 true 。在下面配置 SecurityContextLogoutHandler 。更多信息，请查看 JavaDoc。
* 增加一个 LogoutHandler 。SecurityContextLogoutHandler 被默认添加为最后一个 LogoutHandler 。
* 允许登出成功后，是否删除指定名字的 cookies 。这是显示添加  CookieClearingLogoutHandler 的快捷使用方式。

> 登出配置当然也可以使用 XML 命名空间方式来做。请查询 Spring Security XML Namespace 章节关于 logout element 的内容来获取更详细的内容。

通常，为了配置登出功能，你可以添加 `LogoutHandler` 和/或 `LogoutSuccessHandler` 实现。在更多场景下，这些 handlers 会在背后使用 fluent API 来完成。



##### 6.5.1 LogoutHandler

通常，`LogoutHandler` 实现说明它是能够参与登出实现的类。他们被用来进行必要的清理工作。因此，他们不应该抛出异常。框架提供了多个实现：

* PersistentTokenBasedRememberMeService
* TokenBasedRememberMeService
* CookieClearingLogoutHandler
* CsrfLogoutHandler
* SecurityContextLogoutHandler
* HeaderWriterLogoutHandler

请阅读 [10.5.4节， Remember-Me 接口和实现]()，来获取更多细节。



##### 6.5.2 LogoutSuccessHandler

`LogoutSuccessHandler` 在 `LogoutFilter` 成功处理登出之后被调用，用来处理，例如，重定向或者转发到合适远端地址。请注意，这个接口和 `LogoutHandler` 非常类似，但是会抛出异常。

下面的实现是框架提供的：

* SimpleUrlLogoutSuccessHandler
* HttpStatusReturningLogoutSuccessHandler

正如之前提到的，你并不需要直接指定 `SimpleUrlLogoutSuccessHandler` 。反之，fluent API 提供了一个快捷方式来操作，通过设置 `logoutSuccessUrl()` 。在内部，这将设置一个 `SimpleUrlLogoutSuccessHandler` 。登出成功后请求被重定向到提供的 URL 地址。默认地址是 `/login?logout` 。

在 REST API 场景下，`HttpStatusReturningLogoutSuccessHandler` 是很有意思的。在登出成功之后不是重定向到指定地址，而是用 `LogoutSuccessHandler` 提供的一个普通 HTTP 状态码返回。如果没有特别指定，默认是 200。



##### 6.5.3 更多与登出相关的参考

- [Logout Handling](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#ns-logout)
- [Testing Logout](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#test-logout)
- [HttpServletRequest.logout()](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#servletapi-logout)
- [Section 10.5.4, “Remember-Me Interfaces and Implementations”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-impls)
- [Logging Out](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#csrf-logout) 在 CSRF 情境下的注意事项
- [Single Logout](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#cas-singlelogout) (CAS 协议)
-  [logout element](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#nsa-logout) 在 Spring Security XML Namespace 章节的文档



#### 6.6 OAuth 2.0 客户端

OAuth 2.0 客户端特性支持 OAuth 2.0 Authorization 框架定义的客户角色。

以下是可用的重要特性：

* Authorization Code Grant （认证码授权）
* Client Credentials Grant （客户凭证授权）
* 基于 Servlet 环境的 `WebClient` 扩展（用来保护对资源的请求）。

`HttpSecurity.oauth2Client()` 提供了许多配置选项来配置 OAuth 2.0 客户端。下面的代码展示了，对`oauth2Client()` DSL 全部可用的配置选项：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .clientRegistrationRepository(this.clientRegistrationRepository())
                .authorizedClientRepository(this.authorizedClientRepository())
                .authorizedClientService(this.authorizedClientService())
                .authorizationCodeGrant()
                    .authorizationRequestRepository(this.authorizationRequestRepository())
                    .authorizationRequestResolver(this.authorizationRequestResolver())
                    .accessTokenResponseClient(this.accessTokenResponseClient());
    }
}
```

接下来的章节，会仔细研究这些可选配置的细节：

- [Section 6.6.1, “ClientRegistration”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration)
- [Section 6.6.2, “ClientRegistrationRepository”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-client-registration-repo)
- [Section 6.6.3, “OAuth2AuthorizedClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorized-client)
- [Section 6.6.4, “OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorized-repo-service)
- [Section 6.6.5, “RegisteredOAuth2AuthorizedClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-registered-authorized-client)
- [Section 6.6.6, “AuthorizationRequestRepository”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorization-request-repository)
- [Section 6.6.7, “OAuth2AuthorizationRequestResolver”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-authorization-request-resolver)
- [Section 6.6.8, “OAuth2AccessTokenResponseClient”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#oauth2Client-access-token-client)



##### 6.6.1 ClientRegistration

`ClientRegistration` 代表了注册到 OAuth 2.0 或者 OpenID Connect 1.0 Provider 的客户端。

一个客户端注册类持有许多信息，例如，客户 ID ，客户端密钥，授权认证类型，重定向 URL， 范围，授权 URI ，等等其他细节。

以下是 `ClientRegistration` 和它的属性：

```java
public final class ClientRegistration {
    private String registrationId;  
    private String clientId;    
    private String clientSecret;    
    private ClientAuthenticationMethod clientAuthenticationMethod;  
    private AuthorizationGrantType authorizationGrantType;  
    private String redirectUriTemplate; 
    private Set<String> scopes; 
    private ProviderDetails providerDetails;
    private String clientName;  

    public class ProviderDetails {
        private String authorizationUri;    
        private String tokenUri;    
        private UserInfoEndpoint userInfoEndpoint;
        private String jwkSetUri;   
        private Map<String, Object> configurationMetadata;  

        public class UserInfoEndpoint {
            private String uri; 
            private AuthenticationMethod authenticationMethod;  
            private String userNameAttributeName;   

        }
    }
}
```

* registrationId ： ClientRegistration 的唯一标识符
* clientId ： 客户端标识符
* clientSecret ： 客户端密钥
* clientAuthenticationMethod ： 用于通过 Provider 对客户端身份进行认证的方法。支持的值是 **basic** 和  **post** 。
* authorizationGrantType ： 授权认证类型。支持的类型有 authorization_code （授权码）， implicit（简化）， client_credentials（客户端）。
* redirectUriTemplate ： 在终端客户认证成功，并拥有访问权限之后，认证服务器重定向到终端用户代理的客户端注册的重定向 URI 。（The client’s registered redirect URI that the *Authorization Server* redirects the end-user’s user-agent to after the end-user has authenticated and authorized access to the client.）
* scopes ： 在客户端认证过程中，认证的范围，例如，openid，email 或者 profile 。
* clientName ： 用户使用的用户名。在特殊场景下可能会用到用户的用户名，例如在自动生成的登录页面展示用户名。
* authorizationUri ： 认证服务器的认证终端 URI 。
* tokenUri ： 认证服务器的令牌终端 URI 。
* jwkSetUri ： 从认证服务器取回 JSON Web Key（JWK）集合的 URI 。其中包含机密的秘钥，用来验证 ID 令牌的 JSON Web Signature（JWS） ，也可以用来验证 UserInfo Response 。
* configurationMetadata ： OpenID Provider Configuration Infomation 。只有当 Spring Boot 2.x 的 spring.security.oauth2.client.provider.[providerId].issuerUri 属性被配置了，才会生效。
* （userInfoEndpoint）uri ： 用来访问经过验证的终端用户的声明/属性的 UserInfo Endpoint URI 。
* （UserInfoEndpoint）authenticationMethod ： 用来向 UserInfo Endponit 发送登录 token 的认证方法。支持的值有 **header** ， **form** 和 **query** 。
* userNameAttributeName ：在 UserInfo Response 中返回的属性名，指向终端用户的名字或者标识符。



##### 6.6.2 ClientRegistrationRepository

`ClientRegistrationRepository` 作为 OAuth 2.0 / OpenID Connect 1.0 `ClientRegistration` 的源。

> 客户端注册信息最终在相关的认证服务器上存储和维护。这个源提供了获取主要客户端注册信息子集的能力，这个子集也是存储的认证服务器上。

Spring Boot 2.x 自定配置将 `spring.security,oauth2.registration.[registrationId]` 下的所有属性绑定到 `ClientRegistration` ，并把每一个 `ClientRegistration` 存储在 `ClientRegistrationRepository` 中。

> 默认的 `ClientRegistrationRepository` 是 `InMemoryRegistrationRepository` 。

自动注入同样注册 `ClientRegistrationRepository` 为一个 `ApplicationContext` 中 `@Bean` ，因此如果别的应用需要这个 bean ，就可以依赖注入。

下面是一个示例：

```java
@Controller
public class OAuth2ClientController {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @RequestMapping("/")
    public String index() {
        ClientRegistration googleRegistration =
            this.clientRegistrationRepository.findByRegistrationId("google");

        ...

        return "index";
    }
}
```



##### 6.6.3 OAuth2AuthorizedClient

`OAuth2AuthorizedClient` 是一个已授权的客户端的。当终端使用者（资源所有者）已授权客户访问受保护的资源时，就认为客户是已获得授权的。

`OAuth2AuthorizedClient` 用来将 `OAuth2AccssToken` （或者可选的 `OAuthRefreshTokne`）和 `ClientRegistration` （客户）以及 资源所有者相关联，后者是终端使用者的授权 `Principal` 。



##### 6.6.4 OAuth2AuthorizedClientRepository / OAuth2AuthorizedClientService

`OAuth2AuthorizedClientRepository` 的任务是在 Web 请求之间，持久化 `OAuth2AuthorizedClient(s)` 。然而， `OAuth2AuthorizedClientService` 的主要作用是在应用级别管理 `OAuth2AuthorizedClient` 。

从开发者角度， `OAuth@AuthorizedClientRepository` 或 `OAuthorizedClientService` 提供了寻找与客户端关联的 `OAuth2AccessToken` 的功能，以便能够是用来它初始化对受保护资源的请求。

> Spring Boot 2.x 在自动配置中注册了一个 `OAuthorizedClientRepository` 和/或 `OAuthorizedClientService` `@Bean` 在 `ApplicationContext` 。

开发者可能也会注册一个 `OAuthorizedClientRepository` 或 `OAuthAuthorizedClientService` `@Bean` 到 `ApplicationContext` 中（重写 Spring Boot 的自动配置），这样就能够寻找与特定的 `ClientRegistration` （客户端）相关联的 `OAuth2AccessToken` 。

下面是一个示例：

```java
@Controller
public class OAuth2LoginController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @RequestMapping("/userinfo")
    public String userinfo(OAuth2AuthenticationToken authentication) {
        // authentication.getAuthorizedClientRegistrationId() returns the
        // registrationId of the Client that was authorized during the oauth2Login() flow
        OAuth2AuthorizedClient authorizedClient =
            this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "userinfo";
    }
}
```



##### 6.6.5 RegisteredOAuth2AuthorizedClient

`@RegisteredOAuth2AuthorizedClient` 注解能够为 `OAuth2AuthorizedClient` 类型的方法参数注入值。跟通过 `OAuth2AuthorizedClientService` 寻找 `OAuth2AuthorizedClient` 相比，这是一个简单的方法。

```java
@Controller
public class OAuth2LoginController {

    @RequestMapping("/userinfo")
    public String userinfo(@RegisteredOAuth2AuthorizedClient("google") OAuth2AuthorizedClient authorizedClient) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        ...

        return "userinfo";
    }
}
```

`OAuth2AuthorizedClientArgumentResolver` 管理 `@RegisteredOAuth2AuthorizedClient` ，并且提供一下能力：

* 如果客户端还未获得授权，那么 `OAuth2AccessToken` 将会自动请求授权
  * 对 `authorized_code` 来说，这将触发启动请求重定向流程
  * 对 `client_credentials` 来说，`DefaultClientCredentialsTokenResponseClient` 可以从 Token Endpoint 直接获取通行令牌



##### 6.6.6 AuthorizationRequestRepository

`AuthorizationRequestRepository` 负责从 Authorization Request 到达到 Authorization Response 被接收到，获取 `OAuth2AuthorizedRequest` 的持久化内容（回调）。

>  `OAuth2AuthorizationRequest` 被用来关联和验证授权响应。

`AuthorizationRequestRepository` 的默认实现是 `HttpSessionOAuth2AuthorizationRequestRepository` 。这个实现，是把 `OAuth2AuthorizationRequest` 存储在 `HttpSession` 。

如果你想自己实现一个 `AuthorizationRequestRepository` 来把 `OAuth2AuthorizationRequest` 存储在 `Cookie` 。你可以像下面的代码一样配置：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .authorizationCodeGrant()
                    .authorizationRequestRepository(this.cookieAuthorizationRequestRepository())
                    ...
    }

    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }
}
```



##### 6.6.7 OAuth2AuthorizationRequestResolver

`OAuth2AuthorizationRequestResolver` 的主要作用从受保护的 web 请求中解析 `OAuth2AuthorizationRequest` 。默认实现 `DefaultOAuth2AuthorizationRequestResolver` 会匹配（默认）路径 `/oauth2/authorization/{registrationId}` ，并从中提取出 `registrationId` ，并用它位相关联的 `ClientRegistration` 构建一个 `OAuth2AuthorizationRequest` 。

`OAuth2AuthorizationRequestResolver` 的一个主要使用场景是，利用它来解析 OAuth 2.0 Authorization Framework 中定义的标准参数之外的参数。

举例来说， OpenID Connect 通过扩展 OAuth 2.0 Authorization Framework 定义的标准参数，来为 Authorization Code Flow 定义了一下额外的 OAuth 2.0 请求参数。其中一个扩展的参数是 `orimpt` 。

> 可选的。空格分隔。用大小写敏感的 ASCII 字符串值来区分认证服务器是否提示终端使用者需要重认证或者认证成功。定义的值有： none，login，consent，select_account。

下面的例子展示了如何实现一个 `OAuth2AuthorizationRequestResolver` ，并为 `oauth2Login()`方法的认证请求自定义了一个 `prompt=consect` 的请求参数。

```java
@EnableWebSecurity
public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .anyRequest().authenticated()
                .and()
            .oauth2Login()
                .authorizationEndpoint()
                    .authorizationRequestResolver(
                            new CustomAuthorizationRequestResolver(
                                    this.clientRegistrationRepository));    
    }
}

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

    public CustomAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        this.defaultAuthorizationRequestResolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest =
                this.defaultAuthorizationRequestResolver.resolve(request);  

        return authorizationRequest != null ?   
                customAuthorizationRequest(authorizationRequest) :
                null;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(
            HttpServletRequest request, String clientRegistrationId) {

        OAuth2AuthorizationRequest authorizationRequest =
                this.defaultAuthorizationRequestResolver.resolve(
                    request, clientRegistrationId);    

        return authorizationRequest != null ?   
                customAuthorizationRequest(authorizationRequest) :
                null;
    }

    private OAuth2AuthorizationRequest customAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest) {

        Map<String, Object> additionalParameters =
                new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
        additionalParameters.put("prompt", "consent");  

        return OAuth2AuthorizationRequest.from(authorizationRequest)    
                .additionalParameters(additionalParameters) 
                .build();
    }
}
```

* 配置自定义 OAuth2AuthorizationRequestResolver
* 利用 DefaultOAuth2AuthorizationRequestResolver 来解析 OAuth2AuthorizationRequest
* 如果 OAuthAuthorizationRequest 被解析成功了，返回自定义的版本，否则返回 null
* 增加一个自定义参数到 OAuth2AuthorizationRequest.additionalParameters
* 拷贝一个默认的 OAuthAuthorizationRequest ，这会返回一个 OAuthAuthorizationRequest.Builder 以便更多的修改
* 重写默认的 additionalParameters

> `OAuth2AuthorizationRequest.Builder.build()` 构造了一个 `OAuth2AuthorizationRequest.authorizationRequestUri` ，它代表完整的 Authorization Request URI，包含了使用 `application/x-www-form-urlencoded` 的 query 参数。

前面的示例，展示了增加一个自定义参数到标准参数上的常用场景。然而，如果你希望去除或者修改标准参数，或者你的需求要比这更高级，那么你需要得到构造一个 Authorization Request URI 的全部控制权。那么，此时你就需要重写 `OAuth2AuthorizationRequest.authorizationRequestUri` 参数。

下面的例子，展示了一种与前面不同的 `customAuthorizationRequest()` 方法，覆盖了 `OAuth2AuthorizationRequest.authorizationRequestUri` 属性。

```java
private OAuth2AuthorizationRequest customAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest) {

    String customAuthorizationRequestUri = UriComponentsBuilder
            .fromUriString(authorizationRequest.getAuthorizationRequestUri())
            .queryParam("prompt", "consent")
            .build(true)
            .toUriString();

    return OAuth2AuthorizationRequest.from(authorizationRequest)
            .authorizationRequestUri(customAuthorizationRequestUri)
            .build();
}
```



##### 6.6.8 OAuth2AccessTokenResponseClient

`OAuth2AccessTokenResponseClient` 的主要作用是在 认证服务器的 Token Endponit 用认证授权凭证交换访问令牌凭证。

`OAuth2AccessTokenResponseClient` 对 `authorization_code` 的默认实现是 `DefaultAuthorizationCodeTokenResponseClient` ，它使用了 `RestOperations` 在 Token Endpoint 来交换认证码和访问令牌。

`DefaultAuthorizationCodeTokenResponseClient` 是十分灵活的，允许你自定义 Token Request 的预处理和/或 Token Response 的后处理。

如果你需要自定义 Token Request 的预处理，你可以使用 `DefaultAuthorizationCodeTokenResponseClient.setRequestEntityConverter()` 方法，入参为自定义的 `Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>>` 。默认实现 `OAuth2AuthorizationCodeGrantRequestEntityConverter` 构建了一个 `RequestEntity` 代表了标准的 OAuth 2.0 Access Token Request 。当然，提供一个自定义的 `Converter` 会允许你扩展标准的 Token Request，例如添加一个自定义的参数。

> 自定义的 `Converter` 必须返回一个合法的 `RequestEntity` ，这样才能够被预期的 OAuth 2.0 Provider 理解。

另一方面，如果你需要自定义 Token Response 的后处理，你需要使用 `DefaultAuthorizationCodeTokenResponseClient.setRestOperations()` ，入参为一个自定义配置的 `RestOperations` 。默认的 `RestOperations` 如下配置：

```java
RestTemplate restTemplate = new RestTemplate(Arrays.asList(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter()));

restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
```

> 在发送 OAuth 2.0 Access Token Request 时候， Spring MVC 的 `FormHtpMessageConverter` 会被用到。

`OAuth2AccessTokenResponseHttpMessageConverter` 是一个处理 OAuth 2.0 Access Token Response 的 `HttpMessageConverter`。你可以使用 `OAuth2AccessTokenResponseHttpMessageConverter.setTokenResponseConverter()` ，入参是一个自定义的 `Converter<Map<String, String>, OAuth2AccessTokenResponse>`，用来转换 OAuth 2.0 Token Response 参数到一个 `OAuth2AccessTokenResponse` 。

`OAuth2ErrorResponseErrorHandler` 是一个 `ResponseErrorHandler` ，专门来处理 OAuth 2.0 Error（400 Bad Request） 。它用 `OAuth2ErrorHttpMessageConverter` 来转换 OAuth 2.0 Error 参数到一个 `OAuth2Error`。

无论你是自定义一个 `DefaultAuthorizationCodeTokenResponseClient` 还是提供你自己实现的 `OAuth2AccessTokenResponseClient` ，你都需要和如下代码一样的配置：

```java
@EnableWebSecurity
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .oauth2Client()
                .authorizationCodeGrant()
                    .accessTokenResponseClient(this.customAccessTokenResponseClient())
                    ...
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> customAccessTokenResponseClient() {
        ...
    }
}
```



#### 6.7 OAuth 2.0 Login

利用 OAuth 2.0 Login 特性，应用可以使用户通过已有的程序来登录，例如 OAuth 2.0 Provider（例如，Github），或者 OpenID Connect 1.0 Provider（例如，Google）。OAuth 2.0 Login 实现了这种实现场景："Login with Google" 或者 "Login with Github" 。

> OAuth 2.0 Login 使用 Authorization Code Grant 来实现，就是定义在 OAuth 2.0 Authorization Framework 和 OpenID Connect Core 1.0.



##### 6.7.1 Spring Boot 2.x 示例

Spring Boot 2.x 为 OAuth 2.0 Login 带来了完整的自动配置。

这个章节展示了如何配置 OAuth 2.0 Login 示例，使用 Google 作为 Authentication Provider，并且包含了如下的话题：

* 初始化设置
* 设置重定向 URI
* 配置 application.yml
* 启动应用程序



**初始化设置**

使用 Google's OAuth 2.0 认证系统来登录，你必须设置在 Google API 控制台中设置项目来获取 OAuth 2.0 凭证。

> Google's OAuth 2.0 实现符合 OpenID 1.0 规范，并且是 OpenID 认证的

跟随 OpenID Connect 页面的配置，从 “Setting up OAuth 2.0” 章节开始。



**设置重定向 URI**










