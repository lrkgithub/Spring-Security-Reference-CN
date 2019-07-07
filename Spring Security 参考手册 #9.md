### 9 测试

这一章节讨论 Spring Security 支持的测试。

> 为了使用 Spring Security 的测试支持，你必须把 `spring-security-test-5.2.0.BUILD-SNAPSHOT.jar` 作为依赖。



#### 9.1 测试方法安全性

这一章节展示如何使用 Spring Security 的测试支持来测试基于方法的安全性。我们首先介绍 `MessageService` ，这需要用户被授权后才能访问它。

```java
public class HelloMessageService implements MessageService {

    @PreAuthorize("authenticated")
    public String getMessage() {
        Authentication authentication = SecurityContextHolder.getContext()
            .getAuthentication();
        return "Hello " + authentication;
    }
}
```

`getMessage()` 方法的返回值是一个 String，内容是对 Spring Security 的当前 `Authentication` 说 ”Hello“。一个输出示例如下：

```
Hello org.springframework.security.authentication.UsernamePasswordAuthenticationToken@ca25360: Principal: org.springframework.security.core.userdetails.User@36ebcb: Username: user; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_USER; Credentials: [PROTECTED]; Authenticated: true; Details: null; Granted Authorities: ROLE_USER
```

### 

##### 9.1.1 安全测试设置

在我们使用 Spring Security 的测试支持之前，我们必须执行一些设置。一个示例如下：

```java
@RunWith(SpringJUnit4ClassRunner.class) 
@ContextConfiguration 
public class WithMockUserTests {
```

这是一个基本示例，展示 Spring Security 测试的设置。需要重点关注的是：

* @`RunWith` 指示 spring 测试模块应该新建一个 `ApplicationContext` 。这和使用 Spring 现有的测试支持没有区别。如果需要额外的信息，请参考 [Spring Reference](<https://docs.spring.io/spring-framework/docs/4.0.x/spring-framework-reference/htmlsingle/#integration-testing-annotations-standard>) 。
* `@ContextConfiguration` 指示使用什么配置构造一个 `ApplicationContext` 。如果没有特殊的配置，应用汇尝试默认的配置地址。这和使用已经支持的 Spring Test 支持没有区别。如果需要额外的信息，请参考 [Spring Reference](<https://docs.spring.io/spring-framework/docs/4.0.x/spring-framework-reference/htmlsingle/#integration-testing-annotations-standard>) 。

> Spring Security 使用 `WithSecurityContextTestExecutionListener` 来挂钩进入 Spring Test ，这会确保我们的测试使用正确的用户运行。通过在运行测试用例之前，将 `SecurityContextHolder` 注入来完成。如果你正在使用反应式方法安全，你会需要 `ReactorContextTestExecutorListener` ，这会注入 `ReactiveSecurityContextHolder` 。在测试结束之后，会清除 `SecurityContextHolder` 。如果你只需要 Spring Security 相关的支持，可以用 `SecurityTesetExecutionListeners` 来替代 `ContextConfiguration` 。

记得在 `HelloMessageService` 类上加上 `@PreAuthorize` ，因此需要经过身份验证的用户才能调用它。如果我们运行下面的测试，我们可以期待测试会通过：

```java
@Test(expected = AuthenticationCredentialsNotFoundException.class)
public void getMessageUnauthenticated() {
    messageService.getMessage();
}
```



##### 9.1.2 @WithMockUser

问题是 “我们怎么才能作为特殊用户最快速地运行测试？” 答案是 `@WithMockUser` 。接下来的测试会以一个，用户名为 "user"，密码是 "password"，角色为 “ROLE_USER”。

```java
@Test
@WithMockUser
public void getMessageWithMockUser() {
String message = messageService.getMessage();
...
}
```

特别是以下几点：

* 用户名为 “user” 的用户并不存在，以为我们是在模仿用户
* `Authentication` 是以 `UsernamePasswordAuthentcationToken` 的类型注入 `SecurityContext` 中的。
* `Authentcation` 中的 principal 是 Spring Security 的 `User` 对象。
* `User` 有一个 “user” 的用户名，一个 "password" 的密码，一个单独的 `GrantedAuthority` 角色 “ROLE_USER” 被使用。

这是一个很好的示例，因为我们利用了许多的默认设置。假如我们希望以不同的用户名来运行测试呢？接下来的测试会使用 “customUser” 的用户名来运行测试。再说一次，用户并不需要实际存在。

```java
@Test
@WithMockUser(username="admin",roles={"USER","ADMIN"})
public void getMessageWithMockUserCustomUser() {
    String message = messageService.getMessage();
    ...
}
```

如果你不希望值，自动地带上 “ROLE_” 的前缀，我们可以利用用户的属性。举例来说，这个测试会以 “admin” 的用户名，“USER” 和 “ADMIN” 的权限来调用：

```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WithMockUser(username="admin",roles={"USER","ADMIN"})
public class WithMockUserTests {
```

默认情况下，`SecurityContext` 是在 `TestExecutionListener.beforeTestMethod` 事件的时被设置。这祥相当于 Junit 的 `@Before` 之发生的。你可以改为在 `TestExecutionListener.beforeTestExecution` 事件时，这发生在 Junit 的 `@Before` 之后，但是在测试方法被调用之前：

```java
@WithMockUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```



##### 9.1.3 @WithAnonymousUser

使用 `@WithAnonymousUser` 允许以一个匿名用户的身份来运行。这在你希望以特殊用户的身份运行大部分你的测试用例，但是希望以匿名用户的身份运行少部分的测试用例时，是特别方便的。下面的例子中， withMockUser1 和 withMockUser2 会用 @WithMockUser 来运行，而 anonymous 会以一个匿名用户的身份运行：

```java
@RunWith(SpringJUnit4ClassRunner.class)
@WithMockUser
public class WithUserClassLevelAuthenticationTests {

    @Test
    public void withMockUser1() {
    }

    @Test
    public void withMockUser2() {
    }

    @Test
    @WithAnonymousUser
    public void anonymous() throws Exception {
        // override default to run as anonymous user
    }
}
```

默认情况下，`SecurityContext` 是在 `TestExecutionListener.beforeTestMethod` 事件的时被设置。这祥相当于 Junit 的 `@Before` 之前发生的。你可以改为在 `TestExecutionListener.beforeTestExecution` 事件时，这发生在 Junit 的 `@Before` 之后，但是在测试方法被调用之前：

```java
@WithAnonymousUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```



##### 9.1.4 @WithUserDetails

`@WithMockUser` 是一个十分方便的方式开始运行，你可能不会对所有的用例生效。举例来说，对应用来说，期待 `Authentication` 的 principal 是一种特殊的类型是很常见的事情。这样就可以让应用把 principal 定义为自定义类型，并减少与 Spring Security 的耦合。

自定义的 principal 通常是由自定义的 `UserDetailsServcie` 返回，这个自定义的 `UserDetailsService` 返回一个实现了 `UserDetails` 接口和自定义类型的对象。像这样的场景，使用自定义的 `UserDetailsService` 创建的测试用户进行测试是很有用的。这正是 `@WithUserDetails` 的作用。

假设我们有一个 `UserDetailsService` 作为一个 bean 暴露，接下来的测试会以一个 `UsernamePasswordAuthenticationToken` 类型的 `Authentication` 和一个 `UserDetaisService` 返回的用户名为 "user" 的 principal 调用。

```java
@Test
@WithUserDetails
public void getMessageWithUserDetails() {
    String message = messageService.getMessage();
    ...
}
```

我们可以自定义用来从我们的 `UserDetailsService` 中寻找用户的用户名。举例来说，这个测试用例可以被从 `UserDetailsService` 返回的用户名为 “customUsername” 的 principal 来调用。

```java
@Test
@WithUserDetails("customUsername")
public void getMessageWithUserDetailsCustomUsername() {
    String message = messageService.getMessage();
    ...
}
```

我们可以提供精确的 bean 名字来寻找需要的 `UserDetailsService`。举例来说，这个测试用例会 bean 名为 “myuserDetailsService” 的 `UserDetailsServcie` 来寻找 “customUsername” 的用户名。

```java
@Test
@WithUserDetails(value="customUsername", userDetailsServiceBeanName="myUserDetailsService")
public void getMessageWithUserDetailsServiceBeanName() {
    String message = messageService.getMessage();
    ...
}
```

像 `@WithMockUser` ，我们也可以把我们的注解放在类级别上，这样每一个测试都会使用同一个用户。然而，与 `@WithMockUser` 不一样，`@WithUserDetails` 需要这个用户存在。

默认情况下，`SecurityContext` 是在 `TestExecutionListener.beforeTestMethod` 事件的时被设置。这祥相当于 Junit 的 `@Before` 之前发生的。你可以改为在 `TestExecutionListener.beforeTestExecution` 事件时，这发生在 Junit 的 `@Before` 之后，但是在测试方法被调用之前：

```java
@WithAnonymousUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```



##### 9.1.5 @WithSecurityContext

我们已经看到，如果不使用自定义的 `Authentication` principal ，那么`@WithMockUser` 是一个绝好的选择。接下来，我们发现 `@WithUserDetails` 允许我们使用一个自定义的 `UserDetailsService` 来创建我们的 `Authentication` principal ，但是需要这个用户存在。我们现在将看到一个选择，允许最大程度的灵活性。

我们可以用 `@WithSecurityContext` 来注释我们自己的注解，以创造任何我们希望的 `SecurityContext` 。举例来说，我们可能创建一个名字为 `@WithMockCustomUser` 的注解，如下所示：

```java
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockCustomUserSecurityContextFactory.class)
public @interface WithMockCustomUser {

    String username() default "rob";

    String name() default "Rob Winch";
}
```

我们可以看到 `@WithMockCustomUser` 是一个被 `@WithSecurityContext` 注释的注解。这是在通知 Spring Security Test 支持我们需要为测试创建一个 `SecurityContext` 。`@WithSecurityContext` 注解需要我们确定一个 `SecurityContextFactory` 用来创建 `SecurityContext` ，根据我们的 `@WithMockCustomUser` 注解。你可以在下面看到 `WithMockCustomUserSecurityContextFactory` 的实现：

```java
public class WithMockCustomUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockCustomUser> {
    @Override
    public SecurityContext createSecurityContext(WithMockCustomUser customUser) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        CustomUserDetails principal =
            new CustomUserDetails(customUser.name(), customUser.username());
        Authentication auth =
            new UsernamePasswordAuthenticationToken(principal, "password", principal.getAuthorities());
        context.setAuthentication(auth);
        return context;
    }
}
```

我们现在用我们的注解注释一个测试类或者一个测试方法以及 Spring Security 的 `WithSecurityContextTestExecutionListener` 。这会确保我们的 `SecurityContext` 被恰当地注入。

当创建我们的 `WithSecurityContextFactory` 实现时，需要知道他们可以被标准的 Spring 注解注释。举例来说，`WithuserDetailsSecurityContextFactory` 使用 `Autowired` 注解来表示需要注入 `userDetailsService` 。

```java
final class WithUserDetailsSecurityContextFactory
    implements WithSecurityContextFactory<WithUserDetails> {

    private UserDetailsService userDetailsService;

    @Autowired
    public WithUserDetailsSecurityContextFactory(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public SecurityContext createSecurityContext(WithUserDetails withUser) {
        String username = withUser.value();
        Assert.hasLength(username, "value() must be non-empty String");
        UserDetails principal = userDetailsService.loadUserByUsername(username);
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(), principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
```

默认情况下，`SecurityContext` 是在 `TestExecutionListener.beforeTestMethod` 事件的时被设置。这祥相当于 Junit 的 `@Before` 之前发生的。你可以改为在 `TestExecutionListener.beforeTestExecution` 事件时，这发生在 Junit 的 `@Before` 之后，但是在测试方法被调用之前：

```java
@WithAnonymousUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
```




##### 9.1.6 Test Meta Annotation

如果你在你的测试用例中，经常重复使用一个用户，重复设置属性是不理想的。举例来说，如果有许多用例关联到用一个管理用户，用户名为 “admin”，角色为 `ROLE_USER` 和 `ROLE_ADMIN`，你可能需要这样写：

```java
@WithMockUser(username="admin",roles={"USER","ADMIN"})
```

与其在各处重复这样写，你可以使用一个元注解。举例来说，你可以写一个元注解，取名作 `WithMockAdmin`：

```java
@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(value="rob",roles="ADMIN")
public @interface WithMockAdmin { }
```

现在你可以和使用 `@WithMockUser` 一样使用 `@WithMockAdmin` 。

元注解可以与之前描述的任何注解一起工作。比如，我们可以为 `@WithUserDetails("admin")` 也创建一个元注解。



#### 9.2 Spring MVC Test 集成

Spring Security 提供与 Spring MVC Test 的全面集成。



##### 9.2.1 设置 MockMvc 和 Spring Security

为了和 Spring MVC 一起使用 Spring Security ，有必要将 Spring Security 的 `FilterChainProxy` 作为一个 `Filter` 加入。也有必要把 Spring Security 的 `TestSecurityContextHolderPostProcessor` 来支持 [Running as a User in Spring MVC Test with Annotations](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#running-as-a-user-in-spring-mvc-test-with-annotations) 。这可以通过 Spring Security 的 `SecurityMockMvcConfigurers.springSecurity()` 。比如：

> Spring Security 的测试需要 spring-test-4.1.3.RELEASE 以及以上版本的支持

```java
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class CsrfShowcaseTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity()) 
                .build();
    }

...
```

* SecurityMockMvcConfigurers.springSecurity() 会执行所有的设置，以将 Spring Security 和 Spring MVC Test 集成。



##### 9.2.2 SecurityMockMvcRequestPostProcessors

Spring MVC Test 提供了一个方便的接口 `RequestPostProcessor` ，可以用来修改一个请求。Spring Security 提供了许多的 `RequestPostProcessor` 的实现来使测试变得更多简单。为了使用 `RequestPostProcessor` ，需要确保使用了下面的静态引用：

```java
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
```



**使用 CSRF 保护进行测试**

当测试任意的非安全的 HTTP 方法，并使用了 Spring Security 的保护，你必须确保请求中包含了一个合法的 CSRF  token。为了把合法的 CSRF token 作为一个请求参数使用，应该使用如下的配置：

```java
mvc
    .perform(post("/").with(csrf()))
```

如果你喜欢把 CSRF token 作为 header 来使用：

```java
mvc
    .perform(post("/").with(csrf().asHeader()))
```

你也可以提供一个非法的 CSRF token 来进行测试：

```java
mvc
    .perform(post("/").with(csrf().useInvalidToken()))
```



**在 Spring MVC Test 中以用户角色进行测试**

测试时候，应用特性的用户身份进行是十分常见的。下面有两种简单的方式来注入用户：

- [Running as a User in Spring MVC Test with RequestPostProcessor](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#test-mockmvc-securitycontextholder-rpp)
- [Running as a User in Spring MVC Test with Annotations](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#running-as-a-user-in-spring-mvc-test-with-annotations)



**在 Spring MVC Test 中以用户角色利用 RequestPostProcessor 进行测试**

有许多可选的方式把用户和当前的 `HttpServletRequest` 绑定在一起。举例来说，下面的内容以用户的身份运行（用户不需要存在），用户名为 "user"，密码是"password"，角色是"ROLE_USER"。

> 支持通过将用户与 `HttpServletRequest` 绑定在一起工作。为了把请求与 `SecurityContextHolder` 绑定在一起，你需要确保 `SecurityContextPersistenceFilter` 与 `MockMvc` 绑定在一起。有几个方式可以做到：
>
> * 调用 [apply(springSecurity())](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#test-mockmvc-setup)
> * 将 Spring Security 的 `FilterChainProxy` 加入到 `MockMvc` 中。
> * 在使用 `MockMvcBuilders.standaloneSetup` 时，手动地把 `SecurityContextPersistenceFilter` 添加到 `MockMvc` 中可能更有意义。

```java
mvc
    .perform(get("/").with(user("user")))
```

你可以轻松地自定义。比如，下面的测试将以一个用户名为 “username”，密码为 "password"，角色为"ROLE_USER" 和 "ROLE_ADMIN" 的用户（这个用户并不需要存在）来进行。

```java
mvc
    .perform(get("/admin").with(user("admin").password("pass").roles("USER","ADMIN")))
```

如果你自定义了你想要使用的用户，你也可以轻松地指定。比如，下面会使用一个指定的 `UserDetail` 来运行（并不用实际存在），带着一个 `UsernamePasswordAuthenticationToken` ，它有一个指定的 `UserDetails` 的 principal：

```java
mvc
    .perform(get("/").with(user(userDetails)))
```

你可以使用匿名用户：

```java
mvc
    .perform(get("/").with(anonymous()))
```

如果你以一个默认的用户身份来进行测试，但是对一些特殊的请求需要以匿名用户来执行，这是特别有用的。

如果你想定制一个 `Authentication` （可以不必存在），你可以使用下面的设置来进行：

```java
mvc
    .perform(get("/").with(authentication(authentication)))
```

你甚至可以自定义 `SecurityContext` ：

```java
mvc
    .perform(get("/").with(securityContext(securityContext)))
```

我们也可以通过使用 `MockMvcBuilders` 的默认请求来确保以一个特殊的用户来运行所以的测试。比如，下面的测试将以一个用户名为 “username”，密码为 "password"，角色为"ROLE_USER" 和 "ROLE_ADMIN" 的用户（这个用户并不需要存在）来进行：

```java
mvc = MockMvcBuilders
        .webAppContextSetup(context)
        .defaultRequest(get("/").with(user("user").roles("ADMIN")))
        .apply(springSecurity())
        .build();
```

如果你发现你的测试中有很多同样的用户，推荐把用户移到方法中去。比如，你可以在你的 `CustomSecurityMockMvcRequestPostProcessor` 中确定如下的内容：

```java
public static RequestPostProcessor rob() {
    return user("rob").roles("ADMIN");
}
```

现在你可以在 `SecurityMockRequestPostProcessor` 执行一个静态的引入，并在你的测试中使用它：

```java
import static sample.CustomSecurityMockMvcRequestPostProcessors.*;

...

mvc
    .perform(get("/").with(rob()))
```

**使用注解在 Spring MVC Test 中以用户的身份运行**

作为一个备用选择，你可以使用 `RequestProcessor` 来创建你的用户，你可以使用  [Section 9.1, “Testing Method Security”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#test-method) 描述的注解来完成。举例来说，下面的测试会以一个用户名为 "user"，密码为 “password”，角色为 “ROLE_USER” 进行：

```java
@Test
@WithMockUser
public void requestProtectedUrlWithUser() throws Exception {
mvc
        .perform(get("/"))
        ...
}
```

或者，以一个用户名为 "user"，密码为 “password”，角色为 “ROLE_ADMIN” 来进行：

```java
@Test
@WithMockUser(roles="ADMIN")
public void requestProtectedUrlWithUser() throws Exception {
mvc
        .perform(get("/"))
        ...
}
```



**测试 HTTP Basic 认证**

虽然始终可以验证 HTTP Basic，但是要记住 HTTP header 名字，格式和编码方式总有点枯燥。现在可以通过使用 Spring Security 的 `httpBasic` `RequestPostProcessor` 来完成。举例来说，下面是一个片段：

```java
mvc
    .perform(get("/").with(httpBasic("user","password")))
```

这会尝试用 HTTP Basic 来认证一个用户，名字是 “user”，密码是 “password”，确保一下的头部信息被注入到 HTTP 请求中：

```HTTP
Authorization: Basic dXNlcjpwYXNzd29yZA==
```



##### 9.2.3 SecurityMockMvcRequestBuilders

Spring MVC Test 也提供 `RequestBuilder` 接口用来在你的测试中创建 `MockHttpServletRequest` 。Spring Security 提供一些 `RequestBuilder` 实现，这会让你的测试变得更简单。为了使用 Spring Security 的 `RequestBuilder` 实现，一下的静态引用要确保使用：

```java
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.*;
```



**测试基于表单的认证**

使用 Spring Security 的测试支持，你可以轻松地创建一个请求来测试基于表单的认证。比如，下面的代码支持用一个用户名为 “user”，密码为 "password" 和一个有效的 CSRF token 的请求提交到 "/login"。

```java
mvc
    .perform(formLogin())
```

自定义一个请求也是很简单的。比如，下面的代码会用一个用户名为 “admin”，密码为 “pass” 和一个有效的 CSRF token 的请求提交到 “/login”。

```java
mvc
    .perform(formLogin("/auth").user("admin").password("pass"))
```

我们也可以自定义用户名和密码所对应的参数名。比如，下面的代码是把上述请求修改为用户名存放在 HTTP 参数为 “u” 的参数中，密码存放在 HTTP 参数名为 “p” 的参数中。

```java
mvc
    .perform(formLogin("/auth").user("u","admin").password("p","pass"))
```



**测试登出**

虽然用标准的 Spring MVC Test 微不足道，但是你还是可以用 Spring Security 的测试支持让测试登出变得更简单。比如，下面的代码会提交一个 POST 请求到 "/logout" ，并携带一个有效的 CSRF token：

```java
mvc
    .perform(logout())
```

你也可以自定义一个登出 URL。比如，下面的代码片段会提交一个 POST 请求到 "/signout" ，并携带一个 CSRF token：

```java
mvc
    .perform(logout("/signout"))
```



##### 9.2.4 SecurityMockMvcREsultMatchers

有时候，我们会希望对一个请求作出和安全有多的各种断言。为了满足这种需求，Spring Security Test 支持实现了 Spring MVC Test 的 `ResultMatcher` 接口。为了使用 Spring Security 的 `ResultMatcher` 实现，需要确保下面的静态引用被导入：

```java
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.*;
```

#### 

**非授权的断言**

有时，断言没有一个与 `MockMvc` 的调用结果有关的经过授权的用户是有价值的。比如，你可能希望测试提交一个错误的用户名和密码，来确定没有用户被授权。你可以通过 Spring Security 的测试支持，简单地通过如下代码来实现：

```java
mvc
    .perform(formLogin().password("invalid"))
    .andExpect(unauthenticated());
```



**授权的断言**

很多时候，我们都必须断言一个经过授权的用户是否存在。比如，我们可能希望校验我们成功被授权了。我们可以校验我们是否基于表单的登录是否成功，利用如下的代码片段：

```java
mvc
    .perform(formLogin())
    .andExpect(authenticated());
```

如果我们想校验我们的用户角色，可以略微修改一下我们的代码：

```java
mvc
    .perform(formLogin().user("admin"))
    .andExpect(authenticated().withRoles("USER","ADMIN"));
```

另外，我们也可以校验我们的用户名：

```java
mvc
    .perform(formLogin().user("admin"))
    .andExpect(authenticated().withUsername("admin"));
```

我们可以这样连接校验：

```java
mvc
    .perform(formLogin().user("admin").roles("USER","ADMIN"))
    .andExpect(authenticated().withUsername("admin"));
```

我们还可以对身份验证进行任意的断言：

```java
mvc
    .perform(formLogin())
    .andExpect(authenticated().withAuthentication(auth ->
        assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken.class)));
```
