







### 10. Web Application Security



#### 10.5 Remember-Me Authentication



##### 10.5.1 概览

Remember-me 或者 persistent-login 是指 web 站点具有在 session 之间记住 principal 的标志的能力。正常可以通过发送一个 cookie 到浏览器来完成，在将来的会话中会检测到 cookie 的存在，并且造成自动登录。Spring Security 为这些选项提供了必要的钩子，并且有两个具体的 remem-me 实现。一个使用哈希来保证基于 cookie 的 token 的安全，另一个使用数据库或其他持久化存储机制来保存生成的 token。

注意，这两种实现都需要一个 `UserDetailsService` 。如果你正在使用一个不需要 `UserDetailsService` 的授权提供者（举例来说，LDAP 提供者），那么它不能正常工作的，除非你在应用上下文中有一个 `UserDetailsService` bean。



##### 10.5.2 简单基于哈希的 token 方式

这种方式使用哈希来实现一个有用的 remem-me 策略。本质上，在交互授权成功之后，一个 cookie 被发送给浏览器，组成如下：

```
base64(username + ":" + expirationTime + ":" +
md5Hex(username + ":" + expirationTime + ":" password + ":" + key))

username:          As identifiable to the UserDetailsService
password:          That matches the one in the retrieved UserDetails
expirationTime:    The date and time when the remember-me token expires, expressed in milliseconds
key:               A private key to prevent modification of the remember-me token
```

这样的 remember-me token 只在指定的时间内有效，前提是用户名，密码和密钥不变。值得注意的是，这里有一个潜在的安全问题，捕获到的 rememb-me token 在有效期内对任何用户客户端有效。摘要认证也有同样的问题。如果 principal 意识到一个 token 被捕获了，他们可以简单地改变他们的密码，并且立即是所有的问题涉及到的 remember-me 失效。如果需要更严格的安全保护，那么你需要下一章节描述的方式。另外，remember-me 服务应该立即完全不被使用。

如果你熟悉  [namespace configuration](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#ns-config) 章节提到的话题，你可以使能 remember-me 认证，只需要增加 `<remember-me>` 属性：

```xml
<http>
...
<remember-me key="myAppKey"/>
</http>
```

`UserDetailsService` 通常会被自动选择。如果在你的应用上下文中需要不止一个，那么你需要指定一个，通过 `user-service-ref` 属性，对应的名字是你的 `UserDetailsService` bean。



##### 10.5.3 Persistent Token Approach

这个方法基于稍作修改后的 <http://jaspan.com/improved_persistent_login_cookie_best_practice>  这篇文章。为了用命名空间方式使用这个方法，你需要提供一个数据源引用：

```xml
<http>
...
<remember-me data-source-ref="someDataSource"/>
</http>
```

这个数据库应该包含一个 `persistent_logins` 表，以以下的 SQL 创建（或，相等的语句）：

```SQL
create table persistent_logins (username varchar(64) not null,
                                series varchar(64) primary key,
                                token varchar(64) not null,
                                last_used timestamp not null)
```



##### 10.5.4 Remember-Me 接口和实现

Remember-me 和 `UsernamePasswordAuthenticationFilter` 一起使用，并通过 `AbstractAuthenticationProcessingFilter` 中的钩子来实现。它也在 `BasicAuthenticationFilter` 中实现。这个钩子会在合适的时间调用 `RememberMeService`。这个接口看上去像这样：

```java
Authentication autoLogin(HttpServletRequest request, HttpServletResponse response);

void loginFail(HttpServletRequest request, HttpServletResponse response);

void loginSuccess(HttpServletRequest request, HttpServletResponse response,
    Authentication successfulAuthentication);
```

请查看查看 Java Doc 来获得更全面的描述这些方法是做什么的，尽管注意到，在这一阶段上，`AbstractAuthenticationProcessingFilter` 只会调用 `loginFail()` 和 `loginSuccess()` 方法。`autoLogin()` 方法会被 `RememberMeAuthenticationFilter` 调用，每当 `SecurityContextHolder` 不包含一个 `Authentication` 。这个接口因此提供基础的 remember-me 实现，并提供了充分的认证相关事件的通知。每当一个可能的 web 请求包含 cookie 并希望被记住，就委托给实际的实现。这个设计允许任何数量的 remember-me 策略。在上面我们看到 Spring Security 提供了两种实现。我们一次来看看这些实现。



**TokenBasedRememberMeService**
这个实现支持比 [Section 10.5.2, “Simple Hash-Based Token Approach”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-hash-token) 中描述的更简单的方式。`TokenBasedRememberMeServices` 生成一个 `RememberMeAuthenticationToken`，这会被 `RememberMeAuthenticationProvider`处理。此外，`TokenBasedRememberMeServices` 需要一个 `UserDetailsService` ，从中可以获取用户名和密码，用来进行签名比较，然后生成一个包含正确的 `GrantedAuthority` 的 `RememberMeAuthenticationTokne` 。当用户提出登出时，某种登出命令应该被应用提供，以使 cookie 无效。`TokenBasedRememberMeServices` 也实现了 Spring Security 的 `LogoutHandler` 接口，这样就可以和 `LogoutFilter` 一起使用，来自动清理 cookie。

在应用上下文中使能 remember-me 服务的 beans，如下所示：

```xml
<bean id="rememberMeFilter" class=
"org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter">
<property name="rememberMeServices" ref="rememberMeServices"/>
<property name="authenticationManager" ref="theAuthenticationManager" />
</bean>

<bean id="rememberMeServices" class=
"org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices">
<property name="userDetailsService" ref="myUserDetailsService"/>
<property name="key" value="springRocks"/>
</bean>

<bean id="rememberMeAuthenticationProvider" class=
"org.springframework.security.authentication.RememberMeAuthenticationProvider">
<property name="key" value="springRocks"/>
</bean>
```

别忘了增加你的 `RememberMeService` 到你的 `UsernamePasswordAuthenticationFilter.setRememberMeService()` 属性，包括 `RememberMeAuthenticationProvider` 在你的 `AuthenticationManager.setProviders()` 列表，并增加 `RememberAuthenticationFilter` 到你的 `FilterChainProxy` （一般，紧跟着 `UsernamePasswordAuthenticationFilter`）中。



**PersistentTokenBasedRememberMeServices**

这个类可以和 `TokenBasedRememberMeService` 以同样的方式使用，但是它额外需要配置一个 `PersistentTokenRepository` 来存储 tokens。这里有两种标准的实现：

* `InMemoryTokenRepositoryImpl` 这只为了测试目的
* `JdbcTokenRepositoryImpl` 存储 tokens 到数据库中

数据库 schema 在  [Section 10.5.3, “Persistent Token Approach”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#remember-me-persistent-token) 中讨论。



#### 10.6 跨站点请求伪造

这一章节讨论 Spring Security 的 [Cross Site Request Forgery (CSRF)](https://en.wikipedia.org/wiki/Cross-site_request_forgery) 支持。



##### 10.6.1 CSRF 攻击

在我们讨论 Spring Security 是如何保护来自 CSRF 的攻击之前，我们会解释一下什么是 CSRF 攻击。我们来看一下具体的示例，来获得更好的理解。

假设你的银行站点提供了一个表单来允许转移资金到另一个银行账户。举例来说，HTTP 请求可能是这样的：

```HTTP
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly
Content-Type: application/x-www-form-urlencoded

amount=100.00&routingNumber=1234&account=9876
```

现在，假设你在银行网站上进行身份认证后，没有登出，访问了一个恶意的网站。这个恶意网站包含一个 HTML 页面带有一下的表单：

```HTML
<form action="https://bank.example.com/transfer" method="post">
<input type="hidden"
    name="amount"
    value="100.00"/>
<input type="hidden"
    name="routingNumber"
    value="evilsRoutingNumber"/>
<input type="hidden"
    name="account"
    value="evilsAccountNumber"/>
<input type="submit"
    value="Win Money!"/>
</form>
```

你希望赢钱，所以你点击了提交按钮。在这个过程中，你无意中转账了 100 美元到恶意账户。这会发生的原因是，尽管这个恶意站点无法获取你的 cookie，但是这个和你的银行相关的 cookie 仍旧会随着请求发送。

更糟糕的是，整一个过程会被 JavaScript 自动完成。这意味着你甚至不需要点击按钮。所以我们怎么保护我们自己不受这样的攻击呢？



##### 10.6.2 Synchrogazer Token Pattern

这个问题是因为来自银行站点和来自恶意网站的请求是完全一致的。这意味着没有办法拒绝来自恶意网站的请求，并允许来自银行站点的请求。为了对抗 CSRF 攻击，我们需要确保在请求中有一些恶意网站无法提供的东西。

一个解决方案是使用 [Synchronizer Token Pattern](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#General_Recommendation:_Synchronizer_Token_Pattern)。这个解决方案是确保每一个请求都需要，不仅仅是我们的会话 cookie，还有一个随机生成的 token 作为 HTTP 参数。当一个请求被提交，服务端必须确定参数中应该携带的值，并把它和请求中真正的值进行对比。如果这个值不匹配，那么请求就失败了。

我们可以放松期待，只需要每一个 HTTP 请求中携带更新状态的 token。因为同源安全策略确保恶意网站不能解析网站的回答，所以这可以被安全地完成。另外，我们不希望在 HTTP GET 请求中携带随机的 token ，因为这可能导致 tokens 被泄露。

来看一怎么修改我们的示例。假设随机生成的 token 位于 HTTP 参数 _csrf 中。举例来说，转账的请求会像是这样的：

```HTTP
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly
Content-Type: application/x-www-form-urlencoded

amount=100.00&routingNumber=1234&account=9876&_csrf=<secure-random>
```

你会注意到我们增加了 _csrf 参数和随机值。现在恶意网站不能得到正确的 _csrf 值（必须被恶意网站精确提供），因此转账会失败因为服务端会比较传过来的值和期待的值。



##### 10.6.3 什么时候使用 CSRF 保护

什么应该使用 CSRF 保护呢？我们的建议是使用 CSRF 来保护所有请求，哪怕是普通用户使用浏览器发送的正常请求。如果你现在正在创建一个服务，会被非浏览器的用户端使用，那么你可能会希望关闭 CSRF 保护。



**CSRF 保护和 JSON**

一个常见的问题是 “我需要保护来自 JavaScript 的 JSON 请求吗？” 简单地回答是，看情况。然而，你必须非常小心，因为可能有影响 JSON 请求的 CSRF 漏洞存在。举例来说，一个恶意用户可以创建一个 利用 JSON 的 CSRF 请求，如下：

```javascript
<form action="https://bank.example.com/transfer" method="post" enctype="text/plain">
<input name='{"amount":100,"routingNumber":"evilsRoutingNumber","account":"evilsAccountNumber", "ignore_me":"' value='test"}' type='hidden'>
<input type="submit"
    value="Win Money!"/>
</form>
```

这会产生如下的 JSON 串：

```JSON
{ "amount": 100,
"routingNumber": "evilsRoutingNumber",
"account": "evilsAccountNumber",
"ignore_me": "=test"
}
```

如果一个应用没有验证 `Content-Type`，那么可能会暴露这个漏洞。取决于设置，一个 Spring MVC 应用即便验证了 `Content-Type` 仍旧可能暴露漏洞，因为可以更新 URL 后缀，增加 ".json"，如下所示：

```javascript
<form action="https://bank.example.com/transfer.json" method="post" enctype="text/plain">
<input name='{"amount":100,"routingNumber":"evilsRoutingNumber","account":"evilsAccountNumber", "ignore_me":"' value='test"}' type='hidden'>
<input type="submit"
    value="Win Money!"/>
</form>
```



**CSRF 和无状态浏览器应用**

如果我们的应用是无状态的呢？这不一定意味着你受保护了。实际上，对给定的请求，如果用户不需要在浏览器上执行任何动作，那么它仍然容易受到 CSRF 攻击。

举例来说，考虑一个使用自定义 cookie 的来包含所有状态，而不是使用 `JESSIONID` 来认证的应用。当 CSRF 攻击时，自定义的 cookie 会和请求一起发送，这和之前的 `JESSIONID` 一样。

使用 BASIC 认证的用户也容易受到 CSRF 攻击，因为浏览器会自动将应户名和密码包含在任意一个请求中。这个 `JESSIONID` 和 cookie 会随着请求一起发送的示例是同一种方式。



##### 10.6.4 使用 Spring Security CSRF 保护

所以，使用 Spring Security 来保护我们的应用不受 CSRF 攻击的步骤有哪些？使用 Spring Security 的 CSRF 保护的步骤如下：

* 使用正确的 HTTP 动词
* 配置 CSRF 保护
* 包含 CSRF token



**使用正确的 HTTP 动词**

保护不受 CSRF 攻击的第一步是确保我们的站点使用了正确的 HTTP 动词。特别的，在 Spring Security 的 CSRF 支持可以被使用之前，你需要确保你的应用使用了 PATCH，POST，PUT，和/或 DELETE 来对应任何修改状态的请求。

这不是一个 Spring Security 支持的限制，而是一个适当的 CSRF 保护的常规需求。理由是，在一个 HTTP GET 请求中包含私有信息也会造成信息泄露。查看 [RFC 2616 Section 15.1.3 Encoding Sensitive Information in URI’s](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3)  来获得大体的指导，怎么使用 POST 而不是 GET 来处理敏感信息。

**配置 CSRF 保护**

下一步，是在你的应用中加入 CSRF 保护。一些框架使用无效用户的会话来处理无效的 CSRF token，但是这种处理有它自己的问题。相反的，Spring Security 的 CSRF 保护会产生一个 HTTP 403 拒绝访问返回码。这可以通过配置 `AccessDeniedHandler` 来用不同方式处理 `InvalidCsrfTokenException` 来自定义。

至于，Spring Security 4.0，CSRF 保护是由 XML 配置默认开启的。如果你希望关闭 CSRF 保护，相应的 XML 配置可以在下面看到：

```XML
<http>
    <!-- ... -->
    <csrf disabled="true"/>
</http>
```

CSRF 保护在 Java 配置中也是默认开启的。如果你希望关闭 CSRF 保护，相应的 Java 配置如下所示。查看 CSRF() 的 JavaDoc 来了解 CSRF 保护是怎么配置的。

```java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable();
    }
}
```



**包含 CSRF token**



**表单提交**

最后一步，是全包在所有的 PATCH，PUT，POST 和 DELETE 方法中包含 CSRF token。实现它的一种方式是使用 `_csrf` 请求参数来携带当前的 `CsrfToken`。一个使用 JSP 完成这个动作示例如下：

```JSP
<c:url var="logoutUrl" value="/logout"/>
<form action="${logoutUrl}"
    method="post">
<input type="submit"
    value="Log out" />
<input type="hidden"
    name="${_csrf.parameterName}"
    value="${_csrf.token}"/>
</form>
```

更简单的方式是 Spring Security JSP 标记库中的 [the csrfInput tag](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#the-csrfinput-tag) 。

> 如果你正在使用 Spring MVC `<form:form>` 标记或者 [Thymeleaf 2.1+](https://www.thymeleaf.org/whatsnew21.html#reqdata) ，并且使用了 `@EnableWebSecurity` ，那么 `CerfToken` 会自动为你添加。（使用 `CsrfRequestDataValueProcessor`）



**Ajax 和 JSON 请求**

如果你正在使用 JSON，那么使用 HTTP 参数提交 CSRF token 就不太现实。相反，你可以通过 HTTP 头来提交 token。一个典型的模式应该是将 CSRF token 包含在你的 meta 标志中。一个使用 JSP 示例如下：

```JSP
<html>
<head>
    <meta name="_csrf" content="${_csrf.token}"/>
    <!-- default header name is X-CSRF-TOKEN -->
    <meta name="_csrf_header" content="${_csrf.headerName}"/>
    <!-- ... -->
</head>
<!-- ... -->
```

与其手动创建 meta 标记，你可以使用更简单的 Spring Security JSP 标记库中的 [csrfMetaTags tag](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#the-csrfmetatags-tag)。

然后你可以将token 包含在你的 JOSN 请求中。如果你正在使用 jQuery，这可以使用下列方式完成：

```jQuery
$(function () {
var token = $("meta[name='_csrf']").attr("content");
var header = $("meta[name='_csrf_header']").attr("content");
$(document).ajaxSend(function(e, xhr, options) {
    xhr.setRequestHeader(header, token);
});
});
```

作为 JQuery 的另一种选择，我们推荐使用 [cujoJS](https://github.com/cujojs) 的 rest.js。[rest.js](https://github.com/cujojs/rest) 模块提供了与 HTTP 请求一起工作的高级支持，并且以 RESTful 方式响应。一个核心能力是以拦截器的方式对 HTTP 客户端进行拦截并为 HTTP 行为添加上下文的能力。

```JS
var client = rest.chain(csrf, {
token: $("meta[name='_csrf']").attr("content"),
name: $("meta[name='_csrf_header']").attr("content")
});
```

这个配置的客户端可以被应用中任何需要请求受 CSRF 保护的资源的组件共享。JQuery 和 rest.js 之间一个显著的不同是，只有使用配置的客户端发送的请求才会包含 CSRF token，而 JQuery 中所有的请求都会携带 CSRF token。限制请求中携带 CSRF token 范围的能力，有助于防止 CSRF token 泄露给第三方。请查看 [rest.js 参考手册](https://github.com/cujojs/rest/tree/master/docs) 来获得更多的信息。



**CookieCsrfTokenRepository**

有些情境下，用户可能希望持久化 cookie 中的 `CsrfToken`。默认下，`CookieCsrfTokenRepository` 会写入一个名为 `XSRF-TOKEN`，并从一个名为 `X-XSRF-TOKEN` 的头中或一个名为 `_csrf` 的 HTTP 请求参数中读取。这些默认配置来自于 [AngularJS](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)。

你可以使用 XML 方式配置 `CookieCsrfTokenRepository` ：

```XML
<http>
    <!-- ... -->
    <csrf token-repository-ref="tokenRepository"/>
</http>
<b:bean id="tokenRepository"
    class="org.springframework.security.web.csrf.CookieCsrfTokenRepository"
    p:cookieHttpOnly="false"/>
```

> 这个示例显式地设置 `cookieHttpOnly=false`。为了让 JavaScript（例如，Angular JS） 读取它，这是必须的。如果你不需要使用 JavaScript 直接读取 cookie 的能力，那么推荐设置为 `cokieHttpOnly=true` 来提高安全性。

你可以使用 Java 配置方式来配置 `CookieCsrfToenRepository` ：

```java
@EnableWebSecurity
public class WebSecurityConfig extends
        WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}
```

> 这个示例显式地设置 `cookieHttpOnly=false`。为了让 JavaScript（例如，Angular JS） 读取它，这是必须的。如果你不需要使用 JavaScript 直接读取 cookie 的能力，那么推荐忽略 `cokieHttpOnly=false` 的设置，来提高安全性。



##### 10.6.5 CSRF 注意事项

当使用 CSRF 时候，有一些注意事项。



**超时时间**

将期待的 CSRF token 存储在 `HttpSession` 中会是一个问题，那样只要你的 HttpSession 过期，你配置的 `AccessDeniedHandler` 就会收到一个 InvalidCsrfTokenException。如果你是用默认的 `AccessDeniedHandler`，浏览器会收到一个 HTTP 403，并展示一个糟糕的错误信息。

> 大家可能奇怪为什么不把 `CsrfToken` 默认存储在 cookie 中。这是因为有一个众所周知的漏洞，HTTP 头（例如，指定 cookie）可以被另一个域设置。这就是为什么有 `X-Request-With` 在头部时，Ruby On Rails 不再跳过 CSRF 检查。有关如何执行漏洞利用的详细信息，请参阅此webappsec.org线程。 另一个缺点是，通过删除状态（即超时），如果令牌受到损害，您将失去强制终止令牌的能力。

最后，应用可以配置使用 `CookieCsrfTokenRepository` ，它不会过期。正如之前提到的，这不如使用会话安全，但是在很多场景下都是一个足够好的选择。



**登入**

为了保护 [伪造登入请求](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests) ，从表单登入应该和 CSRF 攻击一样受到保护。以为 `CsrfToken` 是存储在 HttpSession 中的，这意味着只要 `CsrfToken` 通过，一个 HttpSession 就会被创建。这在 RESTful 或 无状态 结构下听上去不太好，但是在实际中，实现带有状态的安全是必要的。没有了状态，如果 token 被泄露，我们将什么都做不了。实际上说，CSRF token 是比较小的，应该对我们的架构产生不了太大的影响。

保护表单登入的常用技术是使用一个 JavaScript 方法在表单提交之前，获取合法的 CSRF token。通过这样做，就没有必要考虑会话过期的问题（在前一章节讨论），因为会话正式在表单提交前创建的（假设没有配置 CookieCsrfTokenRepository），所以用户可以停留在登录页面，并在他需要的时候体检用户名和密码。为了到达这个目标，你可以使用 Spring Security 的 `CsrfTokenArgumentResolver` ，并以 [描述的方式](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#mvc-csrf-resolver) 暴露终端。



**登出**

增加 CSRF 会更新 LogoutFilter 只是用 HTTP POST。这确保登出需要一个 CSRF token，那么一个恶意用户就不能强制登出你的账号。

一种方式是使用表单登出。如果你真的需要一个连接，你可以使用 JavaScript 来持有这个连接来执行一个 POST（比如，一个隐藏的表单）。对于使用 JavaScript 的浏览器来说，这是禁止的，你可以选择让这个连接将用户导向到登出页面，来执行这个 POST 方法。

如果你真的希望使用 HTTP GET 来登出，你可以这么做，但是记住这种的来说是不推荐的。举例来说，下面的 Java 配置会对以任何 HTTP 方法请求的 `/logout` URL 执行登出操作：

```java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
    }
}
```



**Multipart（文件上传）**

这里有两个选择来使用 CSRF 保护 multipart/form-data，每一个选择都有它的权衡。

* 在 Spring Security 之前进行 MultipartFilter
* 在 action 中包含 CSRF token

> 在你把 Spring Security 的 CSRF 保护和多文件上传集成之前，确保你可以在没有 CSRF 保护之前上传。更多关于如果使用 Spring 进行多重表单上传的信息，可以在 [17.10 Spring’s multipart (file upload) support](https://docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/mvc.html#mvc-multipart) 章节的 Spring 参考和 MultipartFilter 的 JavaDoc 找到。



**在 Spring Security 之前进行 MultipartFilte**

第一个选择是确保 `MultipartFilter` 放置在 Spring Security 过滤器之前。明确 `MultipartFilter` 在 Spring Security 过滤器之前意味着，在调用 `MultipartFilter` 之前没有经过认证，这就意味着所有用户都可以往你的服务器上上传服务。然而，只有经过认证的用户能够上传一个传递给你的应用的文件。一般来说，这是推荐的方式，因为上传的临时文件对大多数服务器而言都是微不足道的。

使用 Java 配置时，为了确保 `MultipartFilter` 被放置在 Spring Security 过滤器之前，用户可以重写 `beforeSpringSecurityFilterChain` 方法，如下所示：

```java
public class SecurityApplicationInitializer extends AbstractSecurityWebApplicationInitializer {

    @Override
    protected void beforeSpringSecurityFilterChain(ServletContext servletContext) {
        insertFilters(servletContext, new MultipartFilter());
    }
}
```

使用 XML 配置时，为了确保 `MultipartFilter` 被放置在 Spring Security 过滤器之前，用户可以确保在 `web.xml` 中， `MultipartFilter` 的 `<url-mapping>` 属性被放置在 `springSecurityFilterChain` 之前，如下所示：

```XML
<filter>
    <filter-name>MultipartFilter</filter-name>
    <filter-class>org.springframework.web.multipart.support.MultipartFilter</filter-class>
</filter>
<filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>
<filter-mapping>
    <filter-name>MultipartFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
<filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```



**在 action 中包含 CSRF token**

如果允许未授权的用户可以上传临时文件是不可接受的，另一个选择是将 `MutilpartFilter` 放置在 Spring Security 过滤器之后，并将 CSRF 作为一个请求参数包含在表单的 action 属性中。一个 JSP 的示例如下：

```JSP
<form action="./upload?${_csrf.parameterName}=${_csrf.token}" method="post" enctype="multipart/form-data">
```

这种方式的坏处，是一个请求参数可以被泄露。更通用的场景下，将敏感信息放置在 body 或者 headers 来确保它不被泄露被认为是最佳实践。额外的信息可以在 [RFC 2616 Section 15.1.3 Encoding Sensitive Information in URI’s](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3) 中找到。



**HiddenHttpMethodFilter**

`HiddenHttpMethodFilter` 应该在 Spring Security 过滤器之前被放置。通常这是对的，但是在对抗 CSRF 攻击时，这可能会有额外的影响。

注意到，`HiddenHttpMethodFilter` 只能覆盖 HTTP 的 POST 方法，所以它实际上不太能造成任何实际的问题。然而，将它防止在 Spring Security 的过滤器之前仍旧是最佳实践。



##### 10.6.6 覆盖默认配置

Spring Security 的目标是提供保护用户用户免受攻击的默认配置。但是这不意味着用户只能接受所有的默认配置。

举例来说，你可以提供一个自定义的 `CsrfTokenRepository` 来覆盖 `CsrfToken` 被存储的方式。

你也可以确定一个自定义的 `RequestMatcher` 来决定哪一个请求需要受 CSRF 保护（也许，你不是很在乎登出是否受到攻击）。简单地说，如果 Spring Security 的 CSRF 保护不像你期望的那样表现，你可以自定义它的行为。请查看 [the section called “<csrf>”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#nsa-csrf) 文档，来获取如何使用 XML 来自定义，或者通过 `CsrfConfigurer` 的 JavaDoc 来获取如何使用 Java 配置进行这些自定义行为的信息。



#### 10.7 CORS

Spring 框架提供   [对 CORS 的一流支持](https://docs.spring.io/spring/docs/current/spring-framework-reference/web.html#mvc-cors)。CORS 必须在 Spring Security 之前执行，因为 pre-flight 请求 不会包含任何 cookies （例如，`JESSIONID`）。如果请求不包含任何的 cookies，而 Spring Security 被放置在最前，那么请求会被认定是没有经过授权的（因为请求中没有任何 cookie），并被拒绝。

最简单的确保 CORS 被最先处理的方式是使用 `CorsFilter` 。用户可以提供一个 `CORSConfigurationSource` 把 `CorsFilter` 和 Spring Security 集成在一起，如下所示：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // by default uses a Bean by the name of corsConfigurationSource
            .cors().and()
            ...
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

或者，XML 方式：

```XML
<http>
    <cors configuration-source-ref="corsSource"/>
    ...
</http>
<b:bean id="corsSource" class="org.springframework.web.cors.UrlBasedCorsConfigurationSource">
    ...
</b:bean>
```

如果正在使用 Spring MVC 的 CORS 的支持，你可以忽略指定 `CorsConfigurationSource`，因为 Spring Security 会利用提供给 Spring MVC 的 CORS 配置：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // if Spring MVC is on classpath and no CorsConfigurationSource is provided,
            // Spring Security will use CORS configuration provided to Spring MVC
            .cors().and()
            ...
    }
}
```

或者，XML：

```XML
<http>
    <!-- Default to Spring MVC's CORS configuration -->
    <cors />
    ...
</http>
```



#### 10.8 Security HTTP Response Headers

这一章节讨论 Spring Security 支持给返回添加的多种头部。



##### 10.8.1 默认的 Security 头部

Spring Security 允许用户能够注入默认的安全头部来协助保护他们的应用。Spring Security 的默认设置包括下面的头部：

 

```
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

> `Strict-Transport-Security` 只会加载 HTTPS 请求上

每一个头部的详细细节，可以查看他们对应的章节：

* Cache Control
* Content Type Options
* HTTP Strict Transport Security
* X-Frame-Options
* X-XSS-Protection

尽管这里的每一个头部都被认为是最佳实践，但是应该注意到不是所有的客户端都支持这些头部，所以我们鼓励额外的测试。

你可以自定义这些头部。比如，假设希望你的 HTTP 回复看上去像下面这样：

```
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
```

具体来说，如果你希望所有的回复都有下面的自定义头部：

* X-Frame-Options 来允许来自同一个域的所有请求
* HTTP Strict Transport Security（HSTS）不会被加入到返回中

你可以简答地使用下面的 Java 配置：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
        WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // ...
            .headers()
                .frameOptions().sameOrigin()
                .httpStrictTransportSecurity().disable();
    }
}
```

另外，如果你是用 Spring Security XML 配置，你可以使用如下的设置：

```XML
<http>
    <!-- ... -->

    <headers>
        <frame-options policy="SAMEORIGIN" />
        <hsts disable="true"/>
    </headers>
</http>
```

如果你想要这些默认配置，而想要精确控制所有用到的头部，你可以关闭默认配置。基于 Java 和 XML 配置都在下方提供：

如果你正在使用 Java 配置 Spring Security，可以按如下添加 Cache Control

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    // ...
    .headers()
        // do not use any default headers unless explicitly listed
        .defaultsDisabled()
        .cacheControl();
}
}
```

下面的 XML 只会增加 Cache Control

```XML
<http>
    <!-- ... -->

    <headers defaults-disabled="true">
        <cache-control/>
    </headers>
</http>
```

如果必要，你可以关闭所有的 Spring Security HTTP 头部：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    // ...
    .headers().disable();
}
}
```

XML配置：

```XML
<http>
    <!-- ... -->

    <headers disabled="true" />
</http>
```



**Cache Control**

在过去，Spring Security 要求你为你的 web 应用提供自己的缓存控制。当时这看上去很合理，但是浏览器已经发展到也可以拥有安全连接的缓存。这意味着一个用户可能看到一个需授权页面，登出，然后恶意用户可以使用浏览器缓存来浏览缓存页面。为帮助减少这种情况，Spring Security 提供了缓存控制支持，会将如下头部加入到你的回复中：

```
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
```

简单地增加 `<headers>` 属性，不带子属性，会自动增加 Cache Control，以及其他一些保护。然而，如果你只是希望控制缓存，你可以使能这个特性，使用 Spring Security XML 配置，`<cache-control>` 属性和 `headers@defaults-disable` 属性。

```XML
<http>
    <!-- ... -->

    <headers defaults-disable="true">
        <cache-control />
    </headers>
</http>
```

相似地，你可以使用 Java 配置来仅使能缓存控制：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    // ...
    .headers()
        .defaultsDisabled()
        .cacheControl();
}
}
```

如果你真的希望缓存特定的回复，你的应用可以选择调用 `HttpServletResponse.setHeader(String, String)` 来覆盖 Spring Security 的头部集。

当使用 Spring Web MVC 时，这是常用配置。举例来说，下面的配置可以确保缓存头部为你的所有资源都设置了：

```Java
@EnableWebMvc
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry
            .addResourceHandler("/resources/**")
            .addResourceLocations("/resources/")
            .setCachePeriod(31556926);
    }

    // ...
}
```



**Content Type Options**

历史上的浏览器，包括 Internet Explorer，都会使用  [content sniffing](https://en.wikipedia.org/wiki/Content_sniffing) 来猜测请求的 content type 是什么。这允许浏览器通过猜测没有被明确指定 content type 的资源的 content type 来提高用户体验。举例来说，如果浏览器遇到一个没有被指定 content type 的 JavaScript 文件，它会被允许猜测它的 content type，并执行它。

> 当允许内容被上传时，有许多额外的事情要做（例如，只在不同的域中展示文件，确保 `Content-Type` 头被设置，过滤文件，之类的）。然而，有许多措施是在 Spring Security 能够提供的范围之外的。有一点很重要，必须被指出，当取消 content sniffing 时，你必须按顺序指定 content type，好使它能正常工作。

内容嗅探的问题是，它允许用户利用 polyglots（一种有多种合法内容类型的文件）来执行 XSS 攻击。举例来说，一些站点可能允许用户提交合法的 postscript 文件到 web 站点，并浏览它。恶意用户可能创建一个 postscript 文档，同时也是一个合法的 JavaScript 文件，然而利用它执行一次 XSS 攻击。

内容嗅探可以在回复中添加如下的头部关闭：

```
X-Content-Type-Options: nosniff
```

正如缓存控制属性，`nosniff` 指令会默认被加入，当你使用 `<headers>` 而不带任何子属性时。然而，如果你希望对头部信息更多的控制，你可以使用 `<content-type-options>` 属性，以及 `headers@defaults-disable` 属性，如下所示：

```XML
<http>
    <!-- ... -->

    <headers defaults-disabled="true">
        <content-type-options />
    </headers>
</http>
```

`X-Content-Type-Options` 头可以被 Spring Security 的 Java 配置默认添加。如果你希望对他头部更多的控制，你可以精确地指定 content type，如下所示：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    // ...
    .headers()
        .defaultsDisabled()
        .contentTypeOptions();
}
}
```



**HTTP Strict Transport Security（HSTS）**

当你输入你的银行网站地址时，你是输入 `mybank.com` 还是 `http://mybank.com` ？如果忽视 HTTPS 协议，你可能收到中间人攻击（Man in the Middle attacks）。即使站点执行了一个重定向到 `http://mybank.com`，恶意用户还是可以截取初始的 HTTP 请求，并操纵回复（例如，重定向到 `http://mybank.com`，并窃取他们的凭据）。

许多用户忽视 HTTP 协议，这就是为什么 HTTP Strict Transport Security（HSTS） 被创建的原因。一旦 `mybank.com` 被加入到 HSTS host，一个浏览器可以提前知道 `mybank.com` 就是 `http://mybank.com` 。这就减少了大量的中间人攻击的发生。

> 依据 RFC 6797，HSTS 头只会被注入到 HTTPS 的回复中。为了让浏览器知道头部信息，浏览器必须先信任签发 SSL 证书的 CA 机构，这会在建立连接时用到（不只是 SSL 证书）。

一个站点被标记为 HSTS 的一种方法，是让站点提前加载到浏览器中。另一种方法，是添加 `Strict-Transport-Security` 头到回复中。举例来说，下面的头部会指导浏览器信任这个地址作为 HSTS 地址一年的时间（31536000 s 大约是一年）。

```
Strict-Transport-Security: max-age=31536000 ; includeSubDomains ; preload
```

可选的 `includeSubDomains` 指示 Spring Security 它的子域（例如，`security.mybamk.com`）也同样应该被信任为 HSTS 地址。

可选的 `preload` 指示 Spring Security 这个域应该被体检加载到浏览器作为 HSTS 域。更多关于 HSTS 预加载的内容，请访问 [https://hstspreload.org](https://hstspreload.org/) 。

正如其他头部一样，Spring Security 默认增加 HSTS。你可以自定义 HSTS 头部，使用 `<hsts>` 属性，如下所示：

```XML
<http>
    <!-- ... -->

    <headers>
        <hsts
            include-subdomains="true"
            max-age-seconds="31536000" preload="true" />
    </headers>
</http>
```

相似地，Java 配置：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    // ...
    .headers()
        .httpStrictTransportSecurity()
            .includeSubdomains(true)
            .preload(true)
            .maxAgeSeconds(31536000);
}
}
```



**HTTP Public Key pinning（HPKP）**

HTTP Public Key Pinning （HPKP）是一个安全特性，告诉一个 web 客户端关联一个特定的加密公钥到一个特定的 web 服务端来保护中间人（Man in the Middle，`MITM`）伪造证书攻击。

为了确保 `TLS` 会话中服务端公钥的真伪，公钥被包裹在 X.509 证书中，通常这是由证书认证机构（CA）颁布的。web 客户端例如浏览器，信任了许多这些 CA，他们都可以给任意的域名颁发证书。如果一个攻击者能够攻下一个单独的 CA，那么他就能在大量的 `TLS` 连接上执行 `MITM` 攻击。`HPKP` 可以通过告诉客户端哪一个公钥属于特定的 web 服务器来规避这张风险。HPKP 是一种 Trust On First Use（TOFU）技术。第一次一个 web 服务器通过一个 HTTP 头告诉客户端，哪一个公钥属于它，客户端会保存这个信息知道指定的时间。当这个客户端再次访问这个服务器，它期待的证书包含的公钥指纹，已经被 HPKP 了解。如果服务端提供了一个未知公钥，那么客户端应该向用户提示风险。

> 因为客户端需要根据 SSL 证书验证 pins，HPKP 头部只会被注入 HTTPS 回复中。

一个 pin 验证失败报告是标准的 JSON 结构，这可以被 web 应用的 API 捕获，或者是公共主机 HPKP 报告服务，例如 REPORT-URI。

可选的 `includeSubDomains` 指示告诉浏览器也需要认证给定的 pins 的子域。

与其他头部相反，Spring Security 没有默认添加 HPKP。你可以自定义 HPKP 头部，通过 `<hpkp>` 属性，如下所示：

```XML
<http>
    <!-- ... -->

    <headers>
        <hpkp
            include-subdomains="true"
            report-uri="https://example.net/pkp-report">
            <pins>
                    <pin algorithm="sha256">d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=</pin>
                    <pin algorithm="sha256">E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=</pin>
            </pins>
        </hpkp>
    </headers>
</http>
```

或者是，Java 配置：

```Java
@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
                http
                // ...
                .headers()
                        .httpPublicKeyPinning()
                                .includeSubdomains(true)
                                .reportUri("https://example.net/pkp-report")
                                .addSha256Pins("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
        }
}
```



**X-Frame-Options**

允许你的站点加入到 frame 中可能是一个安全问题。比如说，使用 clever CSS 风格的用户可能被骗点击一些东西，而这些东西是本不准备点击的（例如，视频）。一个用户可能登出银行网站，并点击了某个按钮，给予了其他用户登入的权限。这一类的攻击称之为 `Clickjacking`。

> 另一种先进的处理方式是使用  [the section called “Content Security Policy (CSP)”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#headers-csp).

有许多方式可以减少 clickjacking。比如，保护传统浏览器不受 clickjacking 攻击，可以使用 [frame breaking code](https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet#Best-for-now_Legacy_Browser_Frame_Breaking_Script) 。虽然这不是完美的，frame breaking code 是你能为传统浏览器能做的最好的选择。

一个更先进的方式是使用 `X-Frame-Options` 头：

```
X-Frame-Options: DENY
```



--- 头部信息太多，有需要再完全翻译，先跳过一部分 ---





#### 10.9 Session Managerment

HTTP 会话相关的功能被 `SessionManagementFilter` 和 `SessionAuthenticationStrategy` 接口的组合处理，这是过滤器委托的。典型的使用包括会话固定保护，攻击预防，会话过期探测，限制有多少个会话可以被一个授权用户同时打开。



##### 10.9.1 SessionManagementFilter

`SessionManagementFilter` 检查 `SecurityContextRepository` 与当前 `SecurityContextHolder` 的内容，来决定一个用户在当前请求中是否应该被授权，特别是一个非交互认证机制，例如预认证或者 remember-me。如果源包含一个安全上下文，过滤器什么也不会做。如果不是，thread-local `SecurityContext` 包含一个 （非匿名）的 `Authentiation` 对象，这个过滤器会假设他们已经被过滤器栈中的前一个对象授权了。着就会触发调用 `SessionAuthenticationStrategy`。

如果一个用户当前没有被授权，过滤器会检查一个有效的会话 ID 是否被要求（比如因为超时），并调用配置的 `InvalidSessionStrategy`。后者在用明明空间配置了一个有效的会话 URL 之后，会被使用。



##### 10.9.2 SessionAuthenticationStrategy

`SessionAuthenticationStrategy` 会被 `SessionManagementFilter` 和 `AbstractAuthenticationProcessingFilter` 一起使用，所以乳沟你正在使用一个自定义的表单登陆类，先如此假设，你会需要把它注入到上面的两者中。配置命名空间和自定义的 bean，可能会如下所示：

```XML
<http>
<custom-filter position="FORM_LOGIN_FILTER" ref="myAuthFilter" />
<session-management session-authentication-strategy-ref="sas"/>
</http>

<beans:bean id="myAuthFilter" class=
"org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
    <beans:property name="sessionAuthenticationStrategy" ref="sas" />
    ...
</beans:bean>

<beans:bean id="sas" class=
"org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy" />
```

注意一下默认配置的使用，`SessionFixationProtectionStrategy` 可能造成问题，如果你把 beans 存储在实现了 `HttpSessionBindingListener` 的 session 中，包括 Spring session-scoped beans。查看这个类的 JavaDoc 来获得更多的信息。



##### 10.9.3 并发控制

Spring Security 可以防止一个 principal 对一个同一个应用的多次请求同时授权。许多 ISV 利用它来强制许可，而网络管理员喜欢这个特性，因为它能帮助保护用户共享登陆名。你可以，比如说，停止用户 “Batman” 从两个不同的会话登入 web 应用。你要么无效他们之前的登入，或者可以报告一个错误，当他们再次登入时。注意，如果你正在使用第二种方法，一个用户没有确切地登出（比如在登出之前就关闭了浏览器），将不能再次登入，知道他原来的会话过期。

并发控制是受命名空间支持的，所以请查看一下之前的命名空间章节的最简单的配置。有时，你需要自定义它。

实现使用了特别版本的 `SessionAuthenticationStrategy` ，名字是 `ConcurrentSessionControlAuthenticationStrategy`。

> 之前并发认证的检查是由 `ProviderManager` 来完成的，这会注入到 `ConcurrentSessionController` 中。后者会检查用户尝试连接超出限制的会话。然而， 这个方式需要一个 HTTP 会话在之前就被创建了，这是不可取的。在 Spring Security 3 中，用户首先被 `AuthenticationManager` 认证，一旦他们成功地被授权，一个会话就会被创建，并且检查是否被允许再次打开一个会话。

为了使用并发会话支持，你需要增加如下的配置到 `web.xml`：

```XML
<listener>
    <listener-class>
    org.springframework.security.web.session.HttpSessionEventPublisher
    </listener-class>
</listener>
```

另外，你会需要增加 `ConcurrentSessionFilter` 到你的 `FilterChainProxy` 中。`ConcurrentSessionFilter` 幼两个构造器参数，`sessionRegistry`，通常会指向一个 `SessionRegistryImpl` 实例，和一个 `sessionInformationExpiredStrategy`，定义当会话过期时的策略。一个使用命名空间配置 `FilterChainProxy` 的和其他默认 beans ，会下面这样：

```XML
<http>
<custom-filter position="CONCURRENT_SESSION_FILTER" ref="concurrencyFilter" />
<custom-filter position="FORM_LOGIN_FILTER" ref="myAuthFilter" />

<session-management session-authentication-strategy-ref="sas"/>
</http>

<beans:bean id="redirectSessionInformationExpiredStrategy"
class="org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy">
<beans:constructor-arg name="invalidSessionUrl" value="/session-expired.htm" />
</beans:bean>

<beans:bean id="concurrencyFilter"
class="org.springframework.security.web.session.ConcurrentSessionFilter">
<beans:constructor-arg name="sessionRegistry" ref="sessionRegistry" />
<beans:constructor-arg name="sessionInformationExpiredStrategy" ref="redirectSessionInformationExpiredStrategy" />
</beans:bean>

<beans:bean id="myAuthFilter" class=
"org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
<beans:property name="sessionAuthenticationStrategy" ref="sas" />
<beans:property name="authenticationManager" ref="authenticationManager" />
</beans:bean>

<beans:bean id="sas" class="org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy">
<beans:constructor-arg>
    <beans:list>
    <beans:bean class="org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy">
        <beans:constructor-arg ref="sessionRegistry"/>
        <beans:property name="maximumSessions" value="1" />
        <beans:property name="exceptionIfMaximumExceeded" value="true" />
    </beans:bean>
    <beans:bean class="org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy">
    </beans:bean>
    <beans:bean class="org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy">
        <beans:constructor-arg ref="sessionRegistry"/>
    </beans:bean>
    </beans:list>
</beans:constructor-arg>
</beans:bean>

<beans:bean id="sessionRegistry"
    class="org.springframework.security.core.session.SessionRegistryImpl" />
```

增加一个 `listener` 到 `web.xml` 会导致一个 `ApplicationEvent` 被发布到 Spring `ApplicationContext` 中，每次一个 `HttpSession` 开始或结束。这是很重要的，因为它允许 `SessionRegistryImp`  在会话结束时被通知。没有它，一个用户永远不会再次登陆成功，一旦他们超出了会话的容量，即使他们登出另一个会话或超时。



**查询当前授权用户的 SessionRegistry 和他们的会话**

设置并发控制，通过命名空间配置或者使用纯 bean 配置，都有有用的边际效应，提供你一个可以直接使用的 `SessionRegistry` 到你的应用，所以即使你不想要限制一个用户可能拥有的会话数量，设置这个基础设施还是值得的。你可以设置 `maxiumumSession` 属性为 -1 来允许不受限制的会话。如果你正在使用命名空间，你可以设置一个别名给内部创建的 `SessionRegistry`，使用 `session-registry-alias` 属性，提供一个一个你可以注入到你自己的 bean 中的引用。

`getAllPrincipals()` 方法提供给你并发授权用户的列表。你可以列出用户的会话，通过调用 `getAllSession(Object principal,boolean includeExpiredSessions)` 方法，这会返回一个 `SessionInfomation` 对象的列表。你可以通过调用 `SessionInformation` 实例的 `expireNow()` 方法来世用户的会话过期。当用户返回应用时，他们会被防止继续执行。你可能发现这些方法很有用，比如说，在一个管理应用中。看一下 JavaDoc 来获得更多的信息。



#### 10.10 匿名认证



##### 10.10.1 总览

通常认为当使用 HTTP 时适配一个默认拒绝（“deny-by-default”）是一个好的安全实践。Spring Security 3.0 可以被自定义（关闭）这一点，使用 `<anonymous>` 属性。你不需要配置这里描述的 beans ，除非你想要使用传统的 bean 配置。

三个类一起提供了匿名认证的特性。`AnonymousAuthenticationToken` 是一个 `Authentication` 接口的实现，并存储适用在匿名 principal 的 `GrantedAuthority`。有一个协同的 `AnonmousAuthenticationProvider`，会连接进 `ProviderManager` 中，这样 `AnonymousAuthenticationToken` 会被接受。最终，一个 `AnonymousAuthenticationFilter` ，连接在正常的认证机制后面的，会自动添加一个 `AnonymousAuthenticationToken` 到 `SesucrityContextHolder` ，如果持有任何的 `Authentication` 的话。过滤器的定义和认证提供者都如下所示：

```XML
<bean id="anonymousAuthFilter"
    class="org.springframework.security.web.authentication.AnonymousAuthenticationFilter">
<property name="key" value="foobar"/>
<property name="userAttribute" value="anonymousUser,ROLE_ANONYMOUS"/>
</bean>

<bean id="anonymousAuthenticationProvider"
    class="org.springframework.security.authentication.AnonymousAuthenticationProvider">
<property name="key" value="foobar"/>
</bean>
```

`key` 会在过滤器和 认证提供者之间共享，所以 tokens 可以被前者创造，被后者接受。`userAttribute` 是以 `usernameInTheAuthenticationToklen,gratedAuthority[,grantedAuthority]` 形式表现的。这与 `userMap` 属性的 `InMemoryDaoImpl` 等候使用的语法相似。

正如之前解释的，匿名认证的优势是所有的 URI 模式都可以有安全策略相匹配。比如：

```XML
<bean id="filterSecurityInterceptor"
    class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="httpRequestAccessDecisionManager"/>
<property name="securityMetadata">
    <security:filter-security-metadata-source>
    <security:intercept-url pattern='/index.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/hello.htm' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/logoff.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/login.jsp' access='ROLE_ANONYMOUS,ROLE_USER'/>
    <security:intercept-url pattern='/**' access='ROLE_USER'/>
    </security:filter-security-metadata-source>" 
</property>
</bean>
```



##### 10.10.3 AuthenticationTrustResolver

完善匿名认证讨论的是 `AuthenticationTrustResolver` 接口，和与它相关的 `AuthenticationTrustResolverImpl` 实现。这个接口提供了一个 `isAnonymous(Authentication)` 方法，这允许感兴趣的类考虑到这个特殊类型的认证状态。`ExceptionTranslationFilter` 使用这个接口处理 `AccessDeniedException` 。如果一个 `AccessDeniedException` 被抛出了，一个匿名类型的认证，而不是 403 （forbidden）回复，过滤器会调用 `AuhenticationEntryPoint` ，这样 principal 能够正确认证。这是一个必要的区别，不然另一些 principal 也会被认为是 “授权的”，永远不会有机会通过表单，basic，digest 或者 其他常用的认证机制。

你会经常看到 `ROLE_ANONYMOUS` 属性在上面的拦截器配置中替代了 `IS_AUTHENTICATED_ANONYMOUS`，这和定义访问控制是同一件事情。一个使用 `AuthenticationVoter` 的例子就会在 [authorization chapter](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#authz-authenticated-voter) 看到。它使用一个 `AuthenticationTrustResolver` 来执行这个特定的配置属性，并赋予匿名者访问权限。如果你完全不需要这个功能，那么你可以仍使用 `ROLE_ANONYMOUS`，这回被 Spring Security 认为是标准 `RoleVoter`。



#### 10.11 WebSocket 安全

Spring Security 4 增加了对 Spring WebSocket 的安全性支持。这一章节讨论，如何使用 Spring Security 的 WebSocket 支持。

> 你可以找打一个完整的工作示例，在 <https://github.com/spring-projects/spring-session/tree/master/samples/boot/websocket>。

```
对 JSR-356 的直接支持

Spring Security 不需要提供对 JSR-356 的直接支持，因为这样做，效果很小。因为格式是未知的，Spring Security 为未知的域能做的很少。；另外，JSR- 没有提供一种拦截信息的方式，所以安全操作将会是侵入式的。
```



##### 10.11.1 WebSocket 配置

Spring Security 4.0 采取了通过 Spring Message 为 WebSocket 提供认证的支持。为了使用 Java 配置来配置认证，需要简单地继承 `AbstractSecurityWebSocketMessageBrokerConfigurer` ，并配置 `MessageSecurityMetadataSourceRegistry`。比如说：

```Java
@Configuration
public class WebSocketSecurityConfig
      extends AbstractSecurityWebSocketMessageBrokerConfigurer {  

    protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
        messages
                .simpDestMatchers("/user/*").authenticated();
    }
}
```

这会确保：

* 任何进入的 CONNECT 信息都需要一个有效的 CSRF token 来强制 Same Origin Policy
*  对于任何进入的请求，`SecurityContextHolder` 都在 simpUser 属性中填充用户。
* 我们的信息要求合适的认证。特别的，任何进入的信息以 `/user/` 开始的，都需要 `ROLE_USER`。额外的信息，可以查看 [Section 10.11.3, “WebSocket Authorization”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#websocket-authorization)

Spring Security 也提供 XML 命名空间配置，支持 WebSocket 安全。基于 XML 的可比配置如下：

```XML
<websocket-message-broker>  
    
    <intercept-message pattern="/user/**" access="hasRole('USER')" />
</websocket-message-broker>
```

这会确保：

- 任何进入的 CONNECT 信息都需要一个有效的 CSRF token 来强制 Same Origin Policy
-  对于任何进入的请求，`SecurityContextHolder` 都在 simpUser 属性中填充用户。
- 我们的信息要求合适的认证。特别的，任何进入的信息以 `/user/` 开始的，都需要 `ROLE_USER`。额外的信息，可以查看 [Section 10.11.3, “WebSocket Authorization”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#websocket-authorization)



##### 10.11.2 WebSocket 认证

WebSocket 在 WebSocket 连接建立后，会重用在 HTTP 请求中的相同认证信息。这意味着 `HttpServletRequest` 中的 `Principal` 会交给 WebSocket。如果使用 Spring Security ，`Principal` 和 `HttpServletReqeust` 会被重写。

更具体地说，为了确保用户向你的应用认证了身份，确保你设置了 Spring Security 来认证你基于 web 的应用是必要的。



##### 10.11.3 WebSocket 认证

Spring Security 4.0 采取了通过 Spring Message 为 WebSocket 提供认证的支持。为了使用 Java 配置来配置认证，需要简单地继承 `AbstractSecurityWebSocketMessageBrokerConfigurer` ，并配置 `MessageSecurityMetadataSourceRegistry`。比如说：

```Java
@Configuration
public class WebSocketSecurityConfig extends AbstractSecurityWebSocketMessageBrokerConfigurer {

    @Override
    protected void configureInbound(MessageSecurityMetadataSourceRegistry messages) {
        messages
                .nullDestMatcher().authenticated() 
                .simpSubscribeDestMatchers("/user/queue/errors").permitAll() 
                .simpDestMatchers("/app/**").hasRole("USER") 
                .simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") 
                .simpTypeMatchers(MESSAGE, SUBSCRIBE).denyAll() 
                .anyMessage().denyAll(); 

    }
}
```

这确保了以下几点：

* 任何没有远端地址的信息（例如，包括 MESSAGE 或 SUBSCRIBE 类型，以及之外也类型的信息）都需要用户被授权。
* 任何人都可以订阅 `/user/queue/errors`
* 任何远端地址为 `/app/` 开头的信息，都需要用户拥有 `ROLE_USER`
* 任何以 `/user` 或 `/topic/friend` 开头的，SUBSCRIBE 类型的信息，都需要 `ROLE_USER`
* 任何其他的信息，MESSAGE 或 SUBSCRIBE 都会被拒绝。因为第六点， 我们不需要这一步。但它仍然说明了，一个请求怎么去匹配特殊的信息类型

* 其他的信息都会被拒绝。这是个好主意，可以确保你不漏过所有信息。

Spring Security 也提供 XML 命名空间的配置，来支持 WebSocket 安全。一个可以比较的 XML 配置如下：

```XML
<websocket-message-broker>
    
    <intercept-message type="CONNECT" access="permitAll" />
    <intercept-message type="UNSUBSCRIBE" access="permitAll" />
    <intercept-message type="DISCONNECT" access="permitAll" />

    <intercept-message pattern="/user/queue/errors" type="SUBSCRIBE" access="permitAll" /> 
    <intercept-message pattern="/app/**" access="hasRole('USER')" />      

    
    <intercept-message pattern="/user/**" access="hasRole('USER')" />
    <intercept-message pattern="/topic/friends/*" access="hasRole('USER')" />

    
    <intercept-message type="MESSAGE" access="denyAll" />
    <intercept-message type="SUBSCRIBE" access="denyAll" />

    <intercept-message pattern="/**" access="denyAll" /> 
</websocket-message-broker>
```

这确保了以下几点：

- 任何没有远端地址的信息（例如，包括 MESSAGE 或 SUBSCRIBE 类型，以及之外也类型的信息）都需要用户被授权。
- 任何人都可以订阅 `/user/queue/errors`
- 任何远端地址为 `/app/` 开头的信息，都需要用户拥有 `ROLE_USER`
- 任何以 `/user` 或 `/topic/friend` 开头的，SUBSCRIBE 类型的信息，都需要 `ROLE_USER`
- 任何其他的信息，MESSAGE 或 SUBSCRIBE 都会被拒绝。因为第六点， 我们不需要这一步。但它仍然说明了，一个请求怎么去匹配特殊的信息类型

- 其他的信息都会被拒绝。这是个好主意，可以确保你不漏过所有信息。



**WebSocket 认证提示**

为了正确地保护你的系统，理解 Spring 的 WebSocket 支持是很重要的。



**对于 Message 的 WebSocket 认证**

理解 SUBSCRIBE 和 MESSAGE 类型的却别是很重要的。以及他们如何与 Spring 工作。

考虑一个聊天应用：

* 系统可以发送通知 MESSAGE 到 `/topic/system/notifications` 通知到所有用户
* 客户可以通过订阅 `/topic/system/notifications` 来接受通知

当我们希望用户能够订阅到 `/topic/system/notifications` 时，我们不希望他们把 Message 信息发送到这个地址。如果我们允许用户发送 MESSAGE 到 MESSAG 地址，那么用户就可以绕过系统发送信息给终端。

大体上，一个应用拒绝任何 MESSAGE 信息到 broker 前缀（`/topic/` 或 `/queue/`）地址是很常见的。



**WebSocket 在远端的认证**

理解目的地如何转义也很重要。

考虑一个聊天应用。

* 用户可以发送信息到 `/topic` 开头的地址，以将信息传给特定的用户
* 应用程序看到这些信息，确保 "form" 属性指定了当前用户（不能信任用户）
* 应用发送信息到接收者，使用 `SimpMessageSendingOperations.convertAndSendToUser("toUser","/queue/messages",message)`
* 信息被转发给 `"/queue/user/messages-<sessionid>`

利用上面的应用，我们希望我们的客户监听 `/user/queue`，这回被转发到 `/queue/user/messages-<sessionid>`。然而，我们不希望客户端能监听 `/queue` ，因为这样就允许它看到所有用户的信息。

大体上，一个应用拒绝任何 MESSAGE 信息到 broker 前缀（`/topic/` 或 `/queue/`）地址是很常见的。当然，我们为这种事情提供例外。



**外发的信息**

Spring 在 Flow of Messages 章节描述了信息是如何传达到另一个系统的。理解 Spring Security 只能保护 `clientInboundChannel` 是很重要的。Spring Security 不会尝试保护 `clientoutboundChannle`。

这样做的最重要的理由是性能。许多达到的信息，应该就有多少发出的。与其保护外发的信息，我们鼓励保护定于这些终端的安全。



##### 10.11.4 强制同源策略

浏览器不会为WebSocket连接强制实施同源策略。 这是一个非常重要的考量。



**为什么同源**

考虑下面的场景。一个用户访问 `bank.com` ，认证账户。同一个用户打开另一个浏览器上的页面，访问了一个恶意网页。同源策略确保恶意站点不会访问 `bank.com`。

WebSocket下同源策略不适用。实际上，无论无论 `bank.com` 是否明确精禁止它，恶意网站都可以以用户身份读写数据到 `bank.com`。这意味着，任何用户可以通过 WebSocket 做的事情，恶意网站也可以做。

因为 Sock JS 试着模仿 WebSocket，它也不使用同源策略。这意味着当开发者使用 Socket JS时，需要明确保护他们的应用免受外部的域的恶意攻击。



**Spring WebSocket Allowed Origin**

幸运的是，Spring 4.1.5 开始，WebSocket 和 SocketJs 支持请求访问当前域。Spriung Security 提供了额外保护层来提供深层保护。



--- 如下是 socketJS 部分，由于对 JS 不了解，因此跳过了 ---









