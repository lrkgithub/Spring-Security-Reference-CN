### 10. Web Application Security

大多数 Spring Security 的使用者会在使用 HTTP 和 Servlet API 的应用中使用这个框架。在这一部分，我们会研究一下 Spring Security 是怎么在应用的 web 层面提供认证和访问控制的。我们会看一下在命名空间的表象背后，是哪些类和接口一起提供了 web 层的安全。在一起情景下，有必要使用传统的 bean 配置来提供完全的控制，所以我们会看到如何直接配置类而不是用命名空间。



#### 10.1 The Security Filter Chain

Spring Security 的 web 结构是完全基于标准的 Servlet filter 的。它内部不使用任何 Servlet 或 基于 Servlet 的框架（例如，Spring MVC），所以对于任何特定的 web 技术都没有硬性的关联。它与 `HttpServletRequest` 和 `HttpServletResponse` 交互。而且不关心请求来自于浏览器，有个 web 服务客户端，还是一个 `HttpInvoker` 或者 AJAX 应用。

Spring Security 内部有包含一个过滤器链，其中每一个过滤器都有自己的特殊责任，并且可以随着服务的需要而添加或移除。因为过滤器之间可能有相互依赖，所以过滤器的顺序是很重要的。如果你在使用命名空间配置时，那么过滤器会自动配置好，不需要分别定义任何的 Spring bean ，但是有时，你需要对过滤器链的全部控制，又或者，你使用的特性不支持命名空间，或者你正在使用你定制化版本的类。



##### 10.1.1 DelegatingFilterProxy

当你使用 Servlet filters 时，你需要显式地在 `web.xml` 中定义他们，不然他们会被 Servlet 容器忽略。在 Spring Security 中，过滤器类也是定义在应用上下文中的 Spring beans。因此可以利用 Spring 的依赖注入设施和生命周期管理。Spring 的 `DeletgatingFilterProxy` 提供了 `web.xml` 和应用上下文之间的联系。

当使用 `DelegatingFilterProxy` 时，你会在 `web.xml` 中看到类似这些东西：

```xml
<filter>
<filter-name>myFilter</filter-name>
<filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
<filter-name>myFilter</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>
```

注意过滤器实际上是 `DelegatingFilterProxy` ，而不是真正实现了过滤逻辑的类。`DelegatingFilterProxy` 真正做的，是代理了 通过 Spring 的应用上下文中获取的 `Filter` 的方法。这些使能的 bean 收益于 Spring web 应用上下文生命周期，并且可以灵活配置。 这些 bean 必须实现 `javax.servlet.Filter` 接口，它必须和`filter-name` 元素有同样的名字。阅读 `DelegatingFilterProxy` 的 Javadoc 来获取更多的信息。

 

##### 10.1.2 FilterChainProxy

Spring Security 的 web 结构应该只被一个 `FilterChainProxy` 的实例代理。安全过滤器们不应该自己单独被使用。理论上，应该在应用上下文中申明需要的 Spring Security 过滤器 bean，并为每一个 bean 加一个相关的 `DelegatingFilterProxy` 条目到你的 `web.xml` 中，确保他们的顺序是正确的。但如果你的过滤器很多的话，很快就会使得你的 `web.xml` 混乱且零散。`FilterChainProxy` 使我们只需要添加一个单独的条目到 `web.xml`，就可以处理全部的应用上下文的 web security beans。它和 `DelegatingFilterProxy` 连接使用，就像上面的示例，但是需要把 `filter-name` 设置为 "filterChainProxy" 这个 bean 的名字。这个过滤器链在应用上下文中以同样的 bean 名字申明。以下是个示例：

```xml
<bean id="filterChainProxy" class="org.springframework.security.web.FilterChainProxy">
<constructor-arg>
    <list>
    <sec:filter-chain pattern="/restful/**" filters="
        securityContextPersistenceFilterWithASCFalse,
        basicAuthenticationFilter,
        exceptionTranslationFilter,
        filterSecurityInterceptor" />
    <sec:filter-chain pattern="/**" filters="
        securityContextPersistenceFilterWithASCTrue,
        formLoginFilter,
        exceptionTranslationFilter,
        filterSecurityInterceptor" />
    </list>
</constructor-arg>
</bean>
```

使用命名空间属性 `filter-chain` 是为了方便在应用中设置需要的安全过滤器链。它把一个特定的 URL 模式和一系列的过滤器关联起来，这些过滤器是在 `filters` 属性中定义的 bean names，并把他们和一个 `SecurityFilterBean` 类型的实例连接在一起。`pattern` 属性接受一个 Ant Paths，而且最精确的 URIs 应该出现在前面。在运行时，`FilterChainProxy` 会定位到第一个符合当前 web 请求的 URI 模式，然后把一系列的过滤器对象应用到此次请求上。过滤器会按他们被定义的顺序被调用，所以你对应该到特性 URL 地址的过滤器拥有全部的控制权。

你可能注意到我申明了两个 `SecurityContextPersistenceFilter` 在过滤器链中（`ASC` 是 `allowSessionCreation` 的简称，一个 `SecurityContextPersistenceFilter` 的属性）。因为 web 服务永远不会为未来的请求产生一个 `jessionid`，为每个请求创建一个 `HttpSession` 是一种浪费。如果你有一个大容量的应用，它需要最大程度的扩展性，我们建议你使用上面展示的方式。为小一些的应用，使用一个单独的 `SecurityContextPersistenceFilter` （默认的 `allowSesionCreation` 为 `true`）会更合适。

请注意，`FilterChainProxy` 并没有调用 filter 被配置的标准生命周期方法。我们建议你使用 Spring 的应用上下文接口作为一个选择，正如你处理其他的 Spring bean 一样。

当我们看到如何使用命名空间配置 web 安全时，我们会使用 `DelegatingFilterProxy` ，名字是 “springSecurityFilterChain” 。你现在应该可以看到这是被命名空间创建的 `FilterChainProxy` 的名字。



**传递过滤器链**

你可以使用 `filters=none` 这个属性作为一个选择来提供换一个过滤器 bean 列表。这会完全忽略安全过滤器链中的请求模式。注意这一点，任何符合的路径都将没有授权或者认证服务提供，并且可以自由访问资源。如果你想在请求中利用 `SecurityContext` 的内容，那么它必须通过过滤器链。不然，`SecurityContextHolder` 不会被注入，它的内容会是 null。



##### 10.1.3 过滤器顺序

过滤器的定义顺序是十分重要的。不管哪些过滤器是你真正使用的，顺序应该是如下的：

* `ChannelProcessingFilter`，因为它可能要重定向到不同的协议中
* `SecurityContextPersistentFilter`，这样一个 `SecurityContext` 可以在请求的开始出就可以被加入到 `SecurityContextHolder` 中。所以，当请求结束之后，任何对 `SecurityContext` 的变更都会被拷贝到 `HttpSession` 中。
* `ConcurrentSessionFilter` ，因为它使用 `SecurityContextholder` 的功能，并且需要更新 `SessionRegistry` 来影响 principal 中的持续处理的请求。
* 认证处理机制 -- `UsernamePasswordAuthenticationFilter`，`CasAuthentcationFilter`，`BasicAuthenticationFilter` 之类的，这样 `SecurityContext` 就可以被修改来包含一个合法的 `Authentication` 请求 token。
* `SecurityContextHolderAwareRequestFilter`，如果你需要使用它来安装一个 Spring Security 感知的 `HttpServletRequestWrapper` 到你的 Servlet 容器中。
* `JaasApiIntegrationFilter`，如果一个 `JaasAuthenticationToken` 是在 `SecurityContextHolder` 内部，这个过滤器会把 `FilterChain` 当做一个 `JaasAuthenticationToken` 中的 `Subject` 来处理。
* `RememberMeAuthenticationFilter`，这样如果没有更早的授权处理机制更新了 `SecurityContextHolder` ，而请求提供了一个 cookie 来使能 remember-me 服务，一个合适的被记住的 `Authentication` 会被放入。
* `AnonymousAuthenticationFilter` ，这样如果没有更早的授权机制更新了 `SecurityContextHolder` ，一个匿名的 `Authentication` 对象会被放入。
* `ExceptionTranslationFilter`，来捕获任何的 Spring Security 异常，这样或者一个 Http 错状态码被返回，或者一个合适的 `AuthencationEntryPoint` 被加载。
* `FilterSecurityInterceptor`，来保护 web URIs，并当访问被拒绝时产生异常。



##### 10.1.4 请求匹配和 HttpFireWall

Spring Security 有一些地方，这里有你定义的模式，它们会按顺序匹配进入的请求，以确定是否要处理这些请求。这会发生在两处，一是 `FilterChainProxy` 决定哪一个过滤器链请求应该通过，一处是 `FilterSecurityInteceptor` 决定哪一些安全限制会被加到请求上。理解这个机制，以及什么 URL 值会被用来和你定义的模式进行匹配是很重要的。

The Servlet Specification 为 `HttpServletRequest` 定义了一些属性，这些参数可以被 getter 方法获取，这些正是我们需要和定义的模式进行匹配的。这些属性是 `contextPath`，`servletPath`，`pathInfo` 和 `queryString`。Spring Security 只对应用中的安全路径感兴趣，所以 `contextPath` 会被忽略。不幸的是，Servlet 规范没有确切定义对一个确定的 URI 而言，`servletpath` 和 `pathInfo` 应该包含哪些值。举例来说，每一个 URL 的路径片段都可能包含参数，正如 RFC 2396 定义的。规范没有清楚地表明，这些是否被包含在 `servletPath` 和 `pathInfo` 中，而在不同的 Servlet 容器中他们的表现形式是否一致。当一个应用被部署在一个容器中，而没有从这些值中剥离路径参数，是很危险的，一个攻击者可以添加这些到请求 URL 中，以造成模式匹配意外地成功或失败。另一些 URL 的变化也是有可能的。举例来说，它可能包含一个路径遍历序列（例如，`/../`）或者多重向前划线（`//`）这可能造成模式匹配失败。一些容器在处理 servlet 匹配之前规范化这些东西，但是另一些容器并不会。为了保护这些情况，`FilterChainProxy` 使用 `HttpFireWall` 策略来检查和包裹这些请求。非常规请求会被默认拒绝，路径参数和多重划线出于匹配的原因被移除。因此，`FilterChainProxy` 被用来管理安全过滤器链是很重要的。注意，`servletPath` 和 `pathInfo` 值会被容器解码，所以你的应用应该不含有任何包含分号的合法路径，因为这些路径处于模式匹配的目的被移除了。



正如上面提到的，默认的策略是使用 Ant 风格的路径来匹配，这对大多数用户来说，可能是最好的选择。这个策略在 `AntPathRequestMatcher` 中被实现，这个类利用了 Spring 的 `AntPathMatcher` 来执行大小写敏感的匹配，匹配对象是`servletPath` 和 `pathInfo` ，忽略了 `queryString` 。

如果出于一些原因，你需要一个更强大的匹配策略，你可以使用常亮表达式。这个策略在 `RegexRequestMatcher` 中实现。查看这个类的 JavaDoc 来获取更多的信息。

实践中，我们推荐在业务层使用安全方法，来控制对应用的访问许可，并且不要完全依赖在 web 应用层面定义的安全性质。URLs 是可以变化的，而且要考虑到应用能支持的所有 URLs，以及请求被操作的方式是很困难的。你应该尝试限制自己使用一些简单的 Ant 风格的路径。总是尝试使用 "deny-by-default" 方法，当你在结尾处定义了一个全能通配符（/ 或者），并拒绝访问请求。

在业务层定义安全更强大且难以越过，所以你应该总是尝试着利用好 Spring Security 的安全方法选项。

`HttpFirewall` 还通过拒绝 HTTP Response Header 中的新一行字符来阻止 [HTTP Response Splitting](https://www.owasp.org/index.php/HTTP_Response_Splitting)。



`StrictHttpFirewall` 默认是使用的。这个实现拒绝看上去是恶意的请求。如果这对于你的需求太过于严格，那么你需要自定义哪些类型的请求是你需要拒绝的。然而，你需要明白这可能会使你的应用对一些攻击没有防护。举例来说，如果你希望利用 Spring MVC 的 Matrix Variables，下面的配置可以用在 XML 中：

```xml
<b:bean id="httpFirewall"
      class="org.springframework.security.web.firewall.StrictHttpFirewall"
      p:allowSemicolon="true"/>

<http-firewall ref="httpFirewall"/>
```

也可以使用 Java 编程式的配置同样的配置可以通过暴露 `StrictHttpFirewall` bean 来实现。

```Java
@Bean
public StrictHttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST"));
    return firewall;
}
```

> 如果你正在使用 `new MockHttpServletRequest()`，它用空字符串 "" 来创建一个 HTTP 方法。这是一个合法的 HTTP 方法，但是会被 Spring Security 拒绝。你可以通过 `new MockHttpServletRequest("`
> GET`, "")` 替换原来的方法来解决这个问题。查看 [SPR_16851](https://jira.spring.io/browse/SPR-16851) 请求来改进这一点。

如果你必须允许所有的 HTTP 方法（不建议），你可以使用 `StrictHttpFirewall.setUnsafeAllowAnyHttpMethod(true)`。这也会完全禁用 HTTP 方法的验证。



##### 10.1.5 使用其他基于 Filter 的框架

如果你正在使用其他一些结余 Filter 的框架，那么你必须确保 Spring Security 的过滤器被最先到达。这样 `SecurityContextHolder` 才能及时被注入，以供其他过滤器使用。例如，使用 SiteMesh 来装饰你的 web 页面，或者一个类似 Wicket 之类的使用 Filter 处理请求的 web 框架。



##### 10.1.6 高级命名空间配置

就像你之前在命名空间章节看到的，使用多个 `http` 属性来为不同的 URL 模式定义不同的安全配置。每一个属性都在 `FilterChainProxy` 内部创建一个过滤器链，相应的 URL 会与之相匹配。这些属性会被按他们被描述的顺序被加入，所以描述最精确的模式应该在最前面被定义。这是另一个例子，和上面场景类似，应用支持无状态的 RESTful API ，也支持一个用户用来进行页面登录的普通 web 应用。

```xml
<!-- Stateless RESTful service using Basic authentication -->
<http pattern="/restful/**" create-session="stateless">
<intercept-url pattern='/**' access="hasRole('REMOTE')" />
<http-basic />
</http>

<!-- Empty filter chain for the login page -->
<http pattern="/login.htm*" security="none"/>

<!-- Additional filter chain for normal users, matching all other requests -->
<http>
<intercept-url pattern='/**' access="hasRole('USER')" />
<form-login login-page='/login.htm' default-target-url="/home.htm"/>
<logout />
</http>
```



#### 10.2 核心安全过滤器

有一些关键的过滤器在使用 Spring Security 的 web 应用中总是被使用，所以我们来研究一下这些过滤器以及他们支持的类和接口。我们不会覆盖每一个特性，所以如果你想要过的完整的了解，需要去阅读他们的 JavaDoc。



##### 10.2.1 FilterSecurityInterceptor

当我们在讨论基本访问控制时，已经简单地见过 `FilterSecurityInteceptor`。我们已经在命名空间中配置它，`<intercept-url>` 属性连接起来在内部配置它。现在我们来看一下怎样显式地配置它和 `FilterChainProxy` 一起使用，以及和它配合使用的过滤器 `ExceptionTranslationFilter`。一个典型的配置示例如下：

```java
<bean id="filterSecurityInterceptor"
    class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="accessDecisionManager"/>
<property name="securityMetadataSource">
    <security:filter-security-metadata-source>
    <security:intercept-url pattern="/secure/super/**" access="ROLE_WE_DONT_HAVE"/>
    <security:intercept-url pattern="/secure/**" access="ROLE_SUPERVISOR,ROLE_TELLER"/>
    </security:filter-security-metadata-source>
</property>
</bean>
```

`FilterSecurityInterceptor` 对处理 HTTP 资源的安全负责。它需要对 `AuthenticationManager` 和 `AccessDecisionManager` 的引用。它还提供了适配不同的 URL 地址的属性。请阅读 [the original discussion on these](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#tech-intro-config-attributes)  来获得技术介绍。

`FilterSecurityInterceptor` 可以用两种方式配置配置属性。第一种，如上所示，使用 `<filer-security-metadata-source>` 命名空间属性。这和命名空间配置章节的 `<http>` 属性有些相似，但是 `<intercept-url>` 子属性只使用 `pattern` 和 `access` 属性。逗号被用来限定配置上不同的 HTTP URL 的不同配置。第二种，是编写你自己的 `SecurityMetadataSource`，但是这在这份文档的范围之外了。无论采用何种方式，`SecurityMetadataSource` 负责返回一个 `List<Configuration>` ，它包含了与一个单独的 HTTP URL

关联的所有的配置属性。

应用注意到，`FilterSecurityInterceptor.setSecurityMetadataSource()` 方法实际上期待一个 `FilterInvocationSecurityMetadataSource` 的实例。这是一个标记接口，继承了 `SecurityMetadataSource`。简单地说， `SecurityMetadataSource` 理解 `FilterInvocation` 。为了方便，我们继续引用 `FilterInvocationSecurityMetadataSource` 作为一个 `SecurityMetadataSource`，因为这种区别和大多数用户没有什么关系。



通过命名空间语法创建的 `SecurityMetadataSource` 通过将请求的 URL 与配置的 `pattern` 属性相匹配来获得特殊的 `FilterInvocation` 的配置。这与命名空间配置的方式一致。默认是将所有表达式作为 Apache Ant 路径来对待，而为了更复杂的情况，正则表达式也支持。`request-matcher` 属性被用来确定哪一种模式被使用了。在同一个定义中混合使用多种表达式语法是不允许的。举例来说，之前的表达式用正则表达式来表示而不是 Ant 路径，则会写作：

```xml
<bean id="filterInvocationInterceptor"
    class="org.springframework.security.web.access.intercept.FilterSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="accessDecisionManager"/>
<property name="runAsManager" ref="runAsManager"/>
<property name="securityMetadataSource">
    <security:filter-security-metadata-source request-matcher="regex">
    <security:intercept-url pattern="\A/secure/super/.*\Z" access="ROLE_WE_DONT_HAVE"/>
    <security:intercept-url pattern="\A/secure/.*\" access="ROLE_SUPERVISOR,ROLE_TELLER"/>
    </security:filter-security-metadata-source>
</property>
</bean>
```

模式按他们被定义的顺序处理。所以，更精确的模式应该被定义在列表的更前，而不那么精确的模式被定义在后面一些。这体现在上面的例子中，更精确的 `/secure/super` 模式比不那么精确的 `/secure` 更前面。如果他们反序定义，`/secure/` 模式也总是能匹配，而 `/secure/super` 模式将永远不会被匹配。



##### 10.2.2 ExceptionTranslationFilte

在安全过滤器堆栈中，`ExceptionTranslationFilter` 位于 `FilterSecurityInterceptor` 之上。它本身不处理任何的实际的安全措施，只是处理被安全拦截器抛出的异常，并提供合适的 HTTP response。

```java
<bean id="exceptionTranslationFilter"
class="org.springframework.security.web.access.ExceptionTranslationFilter">
<property name="authenticationEntryPoint" ref="authenticationEntryPoint"/>
<property name="accessDeniedHandler" ref="accessDeniedHandler"/>
</bean>

<bean id="authenticationEntryPoint"
class="org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint">
<property name="loginFormUrl" value="/login.jsp"/>
</bean>

<bean id="accessDeniedHandler"
    class="org.springframework.security.web.access.AccessDeniedHandlerImpl">
<property name="errorPage" value="/accessDenied.htm"/>
</bean>
```



**AuthenticationEntryPoint**

如果用户请求一个安全的 HTTP 资源，但是没有获得授权，`AuthenticationEntryPoint` 会被调用。一个合适的 `AuthenticationException` 或 `AccessDeniedException` 会被调用栈深处的一个安全拦截器抛出。触发这个entry point 的 `commence` 方法。这个类提供了返回给用户的合适的 response 的任务，以便让授权开始。我们在这里使用的是 `LoginUrlAuthenticationEntryPoint` ，作用是重定向请求到一个不同的 URL （典型的是一个登录页面）。实际的实现取决于你在你的应用中使用的认证机制。



**AccessDeniedHandler**

如果你一个用户在被授权之后，尝试访问一个受保护的资源，会发生什么？常规使用下，这不应该发生，因为应用工作流应该仅限有权限的用户操作。举例来说，一个连接到管理页面的 HTML 连接可能会对没有 admin 角色的用户隐藏。你不能依赖应该连接来保证安全，因为总有可能用户通过直接访问 URL 的方式来绕过限制。或者他们可能修改一个 RESTful URL 的一些参数。你的应用必须对付这些场景，不然这绝对是不安全的。你可以典型地使用简单的 web 安全层来为基础的 URLs，并在业务层提供更细致的基于方法的安全保护来确定什么动作是允许的。

如果一个 `AccessDeniedException` 被抛出，而用户已经被授权，这就意味着这个用户尝试着操作他没有权限的动作。这种情况下，`ExceptionTranslationHandler` 会调用第二个策略，`AccessDeniedHandler`。默认下，`AccessDeniedHandler` 被使用，它会返回一个 403（Forbidden） response 到客户端。另外，你可以明确配置一个实例（正如上面的例子），设置一个错误页面的 URL ，这会将请求导向那里。这可以是简单的 `access denied` 页面，例如 `JSP`，或这是一个更复杂的处理器，例如一个 MVC Controller。当然，你可以自己实现这个接口。

提供一个自定义的 `AccessDeniedHandler` 也是可选的，当你在使用命名空间配置你的应用时。查看 [the namespace appendix](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#nsa-access-denied-handler) 来获得更多信息。



**SavedRequest 和 RequestCache 接口**

另一个 `ExceptionTranslationHandler` 的责任是负责保存当前的请求，在调用 `AuthencationEntryPoint`。这允许请求在用户被授权之后，被重新存储（查看 [web authentication](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#tech-intro-web-authentication)）。一个典型的例子是，用户使用表单登录，然后被重定向到用户之前请求的 URL，这是 `SavedRequestAwareAuthenticationSuccessHandler` 完成的。

`RequestCache` 包括存储和获取 `HttpServletRequest` 实例的功能。默认下，`HttpSessionRequestCache` 被使用，它将请求存储在 `HttpSession` 中。`RequestCacheFilter` 负责从缓存中再次存储真正被保存的请求，当用户被导向原始的 URL 地址。

正常情况下，你不应该修改这个功能的任何部分，但是存储请求的处理是一个 “尽最大的努力” 的方式。所以可能有一些情景，默认的配置是无法处理的。这些接口的使用，使这些功能完全可插拔，从 Spring Security 3.0 之后。



##### 10.2.3 SecurityContextPersistenceFilter

我们在 [Technical Overview](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#tech-intro-sec-context-persistence)  章节中介绍了这个重要的过滤器，所以此时你可能希望重读一下这一章节。我们先来看一下如果把它和 `FilterChainProxy` 配置一起使用。一个基本的配置只需要这个 bean 本身：

```xml
<bean id="securityContextPersistenceFilter"
class="org.springframework.security.web.context.SecurityContextPersistenceFilter"/>
```

正如我们之前看到的，这个过滤器有两个主要任务。它负责在 HTTP 请求之间存储 `SecurityContext` 的内容，以及当请求完成之后，清理 `SecurityContextHolder` 。清理上下文里存储的 `ThreadLocal` 是必要的，否则将线程替换为 Servlet 容器中的线程池中的线程时，特定用户的上下文仍旧存在。这个线程在稍后可能还被使用，可能带着错误的凭证进行操作。



**SecurityContextRepository**

从 Spring Security 3.0 开始，加载和存储安全上下文的工作委托给一个单独的策略接口：

```java
public interface SecurityContextRepository {

SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder);

void saveContext(SecurityContext context, HttpServletRequest request,
        HttpServletResponse response);
}
```

`HttpRequestResponseHolder` 是一个存储到达的请求和回复对象的简单容器，并允许实现用包装类替换它。返回的内容会传递给过滤器链。

默认的实现是 `HttpSessionSecurityContextRepository` ，它存安全上下文在 `HttpSession` 属性中。对这个实现，最重要的配置参数是 `allowSessionCreateion` 属性，默认是 `true`，因此允许这个类在需要的时候，创建 session 来为授权的用户存储安全上下文（这只会发生在发生了授权，且安全上下文的内容发生了变化）。如果你不想要一个 session 被创建，那么你可以把这个属性设置为 `false`：

```xml
<bean id="securityContextPersistenceFilter"
    class="org.springframework.security.web.context.SecurityContextPersistenceFilter">
<property name='securityContextRepository'>
    <bean class='org.springframework.security.web.context.HttpSessionSecurityContextRepository'>
    <property name='allowSessionCreation' value='false' />
    </bean>
</property>
</bean>
```

另外，你可以提供一个 `NullSecurityContextRepository` 的实例，一个 [null object](https://en.wikipedia.org/wiki/Null_Object_pattern) 的实现，这会防止安全上下文被存储，尽管一个 session 在请求中已经被创建了。



##### 10.2.4 UsernamePasswordAuthenticationFilter

我们现在看过三个主要的过滤器，总是出现在 Spring Security web 配置中。还有三个被 `<http>` 属性自动创建的过滤器，并且不能被其他的替代。现在缺失的是一个真正的认证机制，一个允许用户被授权的东西。这个过滤器是最常用的过滤器，也是最经常被自定义的。它也提供了命名空间中 `<from-login>` 属性的实现。配置它需要三步：

* 配置一个 `LoginUrlAuthenticationEntryPoint` 和一个登陆页面的 URL，就像我们在上面讨论的，并配置在 `ExceptionTranslationFilter` 之前。
* 实现登陆页面（使用 JSP 或者 MVC 控制器）
* 配置一个 `UsernamePasswordAuthenticationFilter` 实例在应用上下文中
* 把过滤器 bean 加入到你的过滤器链代理中（确保你注意了过滤器的顺序）

登陆表单简单地包括 `username` 和 `password` 输入字段，并发送（POST）到过滤器关联的 URL （默认是 `/login`）。基本的过滤器配置如下所示：

```xml
<bean id="authenticationFilter" class=
"org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter">
<property name="authenticationManager" ref="authenticationManager"/>
</bean>
```

#### 

**认证失败和成功的应用流**

过滤器调用被配置的 `AuthenticationManager` 来处理每一个认证请求。认证成功和失败之后的流程由 `AuthenticationSuccessHandler` 和 `AuthenticationFailureHandler` 策略接口控制。过滤器有相应的属性来设置，这样你就可以完全控制它的行为。有一些标准的实现，例如：`SimpleUrlAuthenticationSuccessHandler`，`SavedRequestAwareAuthenticationSuccessHandler` ，`SimpleUrlAuthenticationFailureHandler`，`ExceptionMappingAuthenticationFailureHandler` 和 `DelegatingAuthenticationFailureHandler` 。看一下这些类的 JavaDoc，以及 `AbstractAuthenticationProcessingFilter` 来了解大概他们是怎么工作的，以及提供的特性。

如果一个认证成功了，认证结果 `Authentication` 对象多被注入到 `SecurityContextHolder` 。配置的 `AuthenticationSuccessHandler` 会被调用来将用户重定向或导向到合适的地址。默认，一个 `SavedRequestAwareAuthenticationSuccessHandler` 会被使用，这意味着用户会被重定向到他们被要求登陆之前的页面。

> `ExceptionTranslationFilter` 缓存了一个用户的原始请求。但一个用户认证之后，就会用这个被缓存的请求得到原始的 URL，并重定向到它。然后原始请求就被重建并替代来使用。

如果一个认证失败了，配置的 `AuthenticationFailureHandler` 会被调用。



#### 10.3 Servlet API 集成

这个章节描述了 Spring Security 是怎么和 Servlet API 集成的。[servletapi-xml](https://github.com/spring-projects/spring-security/tree/master/samples/xml/servletapi)  示例应用描述了所有这些方法的使用。



##### 10.3.1 Servlet 2.5+ 集成



**HttpServletRequest.getRemoteUser()**

[HttpServletRequest.getRemoteUser()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getRemoteUser()) 会返回 `SecurityContextHolder.getContext().getAuthentication().getName()` 的结果，这显然是当前的用户名。如果你希望在你的应用展示当前的用户名，这个方法很有用。另外，通过检查它是否是 null ，可以知道用户是否有授权，还是匿名的。知道用户是否被授权是很有用的，如果需要决定特定的 UI 属性是或应该被展示（例如，一个登出页面应该只有在用户被授权之后才被展示）。



**HttpServletRequest.getUserPrincipal()**

[HttpServletRequest.getUserPrincipal()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#getUserPrincipal()) 会返回 `SecurityContextHolder.getContext().getAuthentication()` 的结果。这意味着它是一个 `Authentication` 实例，典型的是一个 `UsernamePasswordAuthenticationToken` 实例，当使用基于用户名和密码的认证时。 如果你需要增加关于你的用户的额外的信息时，这会很有用。举例来说，你可能创建了一个自定义的 `UserDetailsService` ，它返回自定义的 `UserDetails` 包含你的用户的第一个和最后一个名字。你也可以从以下的代码中获取这些信息：

```java
Authentication auth = httpServletRequest.getUserPrincipal();
// assume integrated custom UserDetails called MyCustomUserDetails
// by default, typically instance of UserDetails
MyCustomUserDetails userDetails = (MyCustomUserDetails) auth.getPrincipal();
String firstName = userDetails.getFirstName();
String lastName = userDetails.getLastName();
```

> 应该注意到，在你的应用中执行这么多的逻辑是一个典型的糟糕实践。相反，应该减少 Spring Security 和 Servlet API 的任何耦合。



**HttpServletRequest.isUserInRole(String)**

[HttpServletRequest.isUserInRole(String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#isUserInRole(java.lang.String)) 能确定 `SecurityContextHolder.getContext().getAuthentication().getAuthorities()` 是否包含传递给 `isUserInRole(String)` 的角色的 `GrantedAuthority` 。通常，用户不应该添加 `ROLE_` 前缀给这个方法，因为这会被自动添加。 举例来说，如果你想要确定当前的用户是否有 "ROLE_ADMIN" 权限，你可以使用一下的代码：

```java
boolean isAdmin = httpServletRequest.isUserInRole("ADMIN");
```

如果要确定一个特定的 UI 组件是否应该被展示，这个方法是很有用的。比如说，你可能希望展示 admin 链接，如果当前的用户是一个 admin。



##### 10.3.2 Servlet 3+ 继承

下面的章节描述 Spring Security 集成的 Servlet 3 的方法。



**HttpServletRequest.authenticate(HttpServletRequest, HttpServletResponse)**

[HttpServletRequest.authenticate(HttpServletRequest,HttpServletResponse)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#authenticate(javax.servlet.http.HttpServletResponse)) 方法可以被用来确定一个用户是否被授权。如果他们没有被授权，配置的 `AuthenticationEntryPoint` 会被用来要求用户去认证（比如，重定向到登陆页面）。



**HttpServletRequest.login(String, String)**

[HttpServletRequest.login(String,String)](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#login(java.lang.String, java.lang.String)) 方法可以被用来使用当前的 `AuthenticationManager` 来认证用户。举例来说，下面的代码会尝试任内政一个用户名为 "user" 和密码是 “password”：

```java
try {
httpServletRequest.login("user","password");
} catch(ServletException e) {
// fail to authenticate
}
```

> 捕获 ServletException 异常不是必要的，如果你希望 Spring Secur 处理失败的认证尝试。



**HttpServletRequest.logout()**

[HttpServletRequest.logout()](https://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html#logout()) 方法可以被用来登出当前用户。

通常，这意味着 `SecurityContextHolder` 将被清理出去，`HttpSession` 将会成为非法的，任何 "Remember Me" 认证会被清理，之类的。然而，配置的 `LogoutHandler` 实现却决于你的 Spring Security 配置。有一点很重要，你需要注意到在 `HttpServletRequest.logout()` 被调用之后，你仍旧负责写一个返回出去。典型地，这会包含一个到欢迎界面的重定向。



**AsyncContext.start(Runnable)**

[AsynchContext.start(Runnable)](https://docs.oracle.com/javaee/6/api/javax/servlet/AsyncContext.html#start(java.lang.Runnable)) 方法会确保你的凭据会被传入到新的线程中。使用 Sprin Security 的并发支持，Spring Security 重写了 `SayncContext.start(Runnable)` 方法，当处理线程时，当前的 `SecurityContext` 会被使用。例如，下面的方法会输出当前用户的 Authentication：

```java
final AsyncContext async = httpServletRequest.startAsync();
async.start(new Runnable() {
    public void run() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        try {
            final HttpServletResponse asyncResponse = (HttpServletResponse) async.getResponse();
            asyncResponse.setStatus(HttpServletResponse.SC_OK);
            asyncResponse.getWriter().write(String.valueOf(authentication));
            async.complete();
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }
});
```



**异步 Servlet 支持**

如果你使用基于 Java 的配置，那么你已经准备好了。但如果你使用 XML 配置，有一些必要的更新需要完成。第一步是确保把你的 XML 更新到至少 3.0 schema：

```xml
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:schemaLocation="http://java.sun.com/xml/ns/javaee https://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
version="3.0">

</web-app>
```

下一步，你需要确保你的 `springSecurityFilterChain` 被配置好来执行异步的请求：

```xml
<filter>
<filter-name>springSecurityFilterChain</filter-name>
<filter-class>
    org.springframework.web.filter.DelegatingFilterProxy
</filter-class>
<async-supported>true</async-supported>
</filter>
<filter-mapping>
<filter-name>springSecurityFilterChain</filter-name>
<url-pattern>/*</url-pattern>
<dispatcher>REQUEST</dispatcher>
<dispatcher>ASYNC</dispatcher>
</filter-mapping>
```

就是它了！现在，Spring Security 会确保你的 `SecurityContext` 也被传播到异步请求中。这意味着当我们提交 

`HttpServletResponse` 的时候，已经没有 `SecurityContext` 了。当 Spring Security 在提交 `HttpServletResponse` 时，Spring Security 自动保存 `SecurityContext` ，它会丢失用户的登陆。

从 Spring Security 3.2 开始，Spring Security 已经聪明到不在提交 `HttpServletResponse` 时自动保存 `SecurityContext` ，只要 `HttpServletRequest.startAsync()` 被调用。



##### 10.3.3 Servlet 3.1+ 集成

接下来的章节描述 Spring Security 集成的 Servlet 3.1 方法。



**HttpServletRequest.changeSessionId()**

[HttpServletRequest.changeSessionId()](https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletRequest.html#changeSessionId()) 是用来对抗 [Session Fixation](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#ns-session-fixation) 攻击的默认方法，在 Servlet 3.1 及以上。



#### 10.4 Basic and Digest Authentication

Basic 和 摘要认证是 web 应用中常用的可选认证机制。Basic 认证经常和无状态的客户端一起使用，在每一次请求时都传递他们的凭据。它使用基于表单的认证来连接两端，一端是基于浏览器的客户，另一端是一个 web 服务端。然而，Basic 认证将密码作为铭文传输，所以它应该只在一个加密的传输层之间传递，比如 HTTPS。



##### 10.4.1 BasicAuthenticationFilter

`BasicAuthenticationFilter` 负责对 HTTP 头中的凭据信息进行 Basic 认证。这可以用来认证来自 Spring 远程协议（例如，Hessian 和 Burlap），同样也可以是常用的浏览器客户端（例如，Firefox 和 Internet Explorer）。HTTP Basic Authentication 管理标准定义在 RFC 1945 ，章节 11 中。`BasicAuthenticationFilter` 符合这个 RFC。Basic Authentication 是一个有吸引力的认证方式，因为它广泛地部署在客户端中，而且实现及其简单（它只是一个 Base64 编码的 username：password，定义在 HTTP 头中）。



**配置**

为了实现 HTTP Basic Authentication，你需要增加一个 `BasicAuthenticationFilter` 到你的过滤器链中。应用上下文应该包含 `BasicAuthenticationFilter` 而且它需要合作者：

```xml
<bean id="basicAuthenticationFilter"
class="org.springframework.security.web.authentication.www.BasicAuthenticationFilter">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="authenticationEntryPoint" ref="authenticationEntryPoint"/>
</bean>

<bean id="authenticationEntryPoint"
class="org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint">
<property name="realmName" value="Name Of Your Realm"/>
</bean>
```

配置的 `AuthenticationManager` 会处理每一个认证请求。如果认证失败了，配置的 `AuthenticationEntryPoint`  会被用来重试认证过程。通常，你会使用一个与 `BasicAuthenticationEntryPoint` 组合的过滤器，它会返回 401 Response 与合适的 头部来重试 HTTP Basic Authentication。如果认证成功了，作为结果的 `Authentcation` 对象会被注入 `SecurityContextHolder` ，像通常那样。

如果认证事件是成功的，或者认证没有被触发，因为 HTTP 头没有包含一个支持的认证请求，过滤器会正常继续。过滤器链被打断，只有在认证失败后，`AuthenticationEntryPoint` 被调用。



##### 10.4.2 DigestAuthenticationFilter

`DigestAuthenticationFilter` 能够处理在 HTTP 头中的摘要认证凭据。Digest Authentication 尝试着解决 Basic Authentication 的许多缺点，特别地，通过确定凭据不会被明文传递。许多用户客户端支持 Digets Authentication，包括 Mozila Firefox 和 Internet Explorer。HTTP Digest Authentication 的管理标准定义在 RFC 2617，它更新了 Digest Authentication 的老版本 RFC 2096。大多数客户端支持 RFC 2617。Spring Security 的 `DigestAuthenticationFilter` 与 RFC 2617 的 ”auth“ 保护质量（qop）兼容，后者还提供了与 RFC 2069 的兼容。Digest Authentication 是一个更有吸引力的认证选择，如果你需要使用未加密的 HTTP（比如，不使用 TLS / HTTPS），并且希望得到最大化的安全认证处理。确实，Digest Authentication 是 WebDAV 强制要求的身份认证，在 RFC 2518 章节 17.1。

> 你不应该在现代应用中使用摘要认证，因为它被认为是不安全的。最明显的问题是，你必须把你的密码以明文，加密的，或者 MD5 格式存储。所有的这些存储格式都被认为是不安全的。你应该使用一种单向自适应密码哈希（例如，bCrypt，PBKDF2，SCrypt，等等）。

Digest Authentication 的核心是 "nonce"。这是服务端生成的值。Spring Security 的 nonce 适应下面的格式。

```
base64(expirationTime + ":" + md5Hex(expirationTime + ":" + key))
expirationTime:   The date and time when the nonce expires, expressed in milliseconds
key:              A private key to prevent modification of the nonce token
```

`DigestAuthenticationEntryPoint` 有一个属性用来指定 `key`，生成 "nonce" tokens，还有 `nonceValiditySecondes` 属性决定超时时间（默认 300，相当于 5 分钟）。只要 nonce 是有效的，摘要会被各种字符串连接在一起，包括用户名，密码，nonce，被请求的 URI，一个客户端生成的 nonc（只是客户端在每次请求时生成的随机值），realm 名字，然后进行 MD5 计算。服务端和客户端都进行摘要计算，产生不一样的哈希值，如果他们包含的值不一样（比如，密码）。在 Spring Security 实现中，如果一个服务端生成的 nonce 只是过期了（摘要是有效的），`DigestAuthenticationEntryPonit` 会发送一个 `stale=true` 头。这告诉客户端不需要修改（因为密码和用户名是正确的），只是再发送一个并使用心得 nonce。

一个合适的 `DigestAuthenticationEntryPoint` 的 `nonceValiditySeconds` 参数的值，取决于你的应用。特别是安全应用，应该注意到一个获取的认证头可以被用来模仿 principal 直到 nonce 中包括的 `expirationTime` 过期。这是选择一个合适的设置时的关键，但一个非常安全的应用不通过 TLC / HTTPS 运行是很不寻常的。

因为 Digest Authentication 更复杂的实现，有许多客户端问题。举例来说，Internet Explorer 不能在同一个  session 的后续请求中显示 ”opaque“ token。Spring Security 过滤器因此封装了所有状态信息到 "nonce" 中。在我们的测试中，Spring Security 的实现与 Mozilla Firefox 和 Internet Explorer 合作是可靠的，比如正确处理 non ce 超时时间之类的。



**配置**

现在，我们回顾一下理论，看下如何使用它。为了实现 Digest Authentication，必须在过滤器链中定义 `DigestAuthenticationFilter` 。应用上下文需要定义 `DigestAuthenticationFilter` 和它需要的配合：

```xml
<bean id="digestFilter" class=
    "org.springframework.security.web.authentication.www.DigestAuthenticationFilter">
<property name="userDetailsService" ref="jdbcDaoImpl"/>
<property name="authenticationEntryPoint" ref="digestEntryPoint"/>
<property name="userCache" ref="userCache"/>
</bean>

<bean id="digestEntryPoint" class=
    "org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint">
<property name="realmName" value="Contacts Realm via Digest Authentication"/>
<property name="key" value="acegi"/>
<property name="nonceValiditySeconds" value="10"/>
</bean>
```

配置的 `UserDetailsService` 是需要的，因为 `DigestAuthenticationFilter` 必须可以直接访问用户的明文密码。Digest Authentication 不能工作，如果你在的 DAO 存储的是加密过的密码。DAO 组件，与 `UserCache` 一起，通常是通过 `DaoAuthenticationProvider` 直接分享的。`authenticationEntryPoint` 属性必须是 `DigestAuthenticationEntryPoint` ，这样 `DigestAuthenticationFilter` 才可以获取正确的 `realmName` 和 `key` 进行摘要计算。 

像 `BasicAuthenticationFilter`，如果认证成功了，一个 `Authentication` 请求 token 会被注入进 `SecurityContext` 中。如果认证事件是成功的，或者因为 HTTP 头中不包含 Digest Authentication 请求信息而导致认证没有被触发，过滤器链会正常执行。只有在认证失败，而且 `AuthenticationEntryPoint` 被调用时，过滤器链才能被打断，正如前面几段讨论的。

Digest Authentication 的 RFC 提供了许多额外的特性来支持未来增加的安全需求。比如说，nonce 可以在每次请求中都更换。除此之外，Spring Security 实现被设计为最小化实现的复杂度（无疑会出现的客户端不兼容），避免在服务端存储状态的需要。你可以去阅读一下 RFC 2617，如果你希望了解更多这些特性的细节。正如我们所知的，Spring Security 的实现确实符合 RFC 的最低标准。

