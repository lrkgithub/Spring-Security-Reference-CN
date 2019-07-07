### 11. 认证

Spring Security 中的高级授权功能是其受欢迎，引人关注程度高的原因之一。不管你选择怎么去认证，选择 Spring Security 提供的机制和 provider，还是集成一个容器，或者使用非 Spring Security 的认证授权，你都会发现有一种一致且简单的方式在你的应用中使用认证服务。

在这一部分，我们会探索不同的 `AbstractSecurityInterceptor` 实现，之前在 Part I 中介绍过的。然后我们去探索怎样通过领域访问控制列表来微调授权机制。



#### 11.1 认证架构



##### 11.1.1 Authorities

正如我们在技术总览中看到的，所有的 `Authentication` 实现都存储了一个 `GrantedAuthority` 对象列表。这代表了赋予给 principal 的 authorities 。`GrantedAuthority` 对象被 `AuthenticationManager` 插入 `Authentication` 中，之后在进行认证决策时，被 `AccessDecisionManager` 读取。

`GrantedAuthority` 是一个只有一个方法的接口：

```Java
String getAuthority();
```

这个方法允许 `AccessDecisionManager` 来获取一个精确代表 `GrantedAuthority` 的 `String`。通过返回一个 `String` 的代表对象，一个 `GrantedAuthority` 可以简单地被绝大多数 `AccessDecisionManager` “读取”。如果一个 `GrantedAuthority` 不能精确地被一个 `String` 表示，那么 `GrantedAuthority` 被认为是 "复杂的"，`getAuthority()` 一定会返回 `null`。

一个复杂的 `GrantedAuthority` 示例，可以是一个存储使用于不同的客户账号的操作，以及权限阈值列表的实现。用一个 `String` 代表这个复杂的 `GrantedAuthority` 可以是比较难的，作为 `getAuthority()` 返回的结果应该返回 `null`。这会指示任意的 `AccessDecisionManager` 需要对 `GrantedAuthority` 有特殊支持，这样才能够理解它的内容。

Spring Security 包括一个具体的 `GrantedAuthority` 实现，`SimpleGrantedAuthority`。这会允许任意用户定义的 `String` 被转换为一个 `GrantedAuthority`。Spring Security 架构中的所有的 `AuthentcationProvider` 都是用 `SimpleGrantedAuthority` 来填充 `Authentication` 对象。



##### 11.1.2 预调用处理

正如我们在 [技术总览](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#secure-objects) 章节看到的，Spring Security 提供了拦截器，来控制器安全对象的访问，例如方法调用或者 web 请求。一个预调用决定是否允许调用继续进行是由 `AccessDecisionManager` 做出的。



**AccessDesignManager**

`AccessDesignManager` 是由 `AbstractSecurityInterceptor` 调用的，并对最终的访问控制决定负责。`AccessDecisionManager` 是一个拥有三个方法的接口：

```Java
void decide(Authentication authentication, Object secureObject,
    Collection<ConfigAttribute> attrs) throws AccessDeniedException;

boolean supports(ConfigAttribute attribute);

boolean supports(Class clazz);
```

`AccessDecisionManager` 的 `decide` 方法要求传入它要求所有相关信息，才可以做出授权决定。特别的，传入安全对象 `Object` 可以是实际安全对象调用中的参数被检查。比如说，我们结社安全对象是一个 `MethodInvocation`。 为任意的 `Customer` 参数查询 `MethodInvocation` 是容易的事，然后在 `AccessDecisionManager` 中实现一些安全逻辑来确保 principal 被允许对该 customer 操作。如果访问被拒绝，那么实现类应该抛出一个 `AccessDeniedException` 异常。

`support(ConfigAttribute)` 方法被 `AbstractSecurityInterceptor` 在启动时调用，来决定 `AccessDecisionManager` 可以处理传入的 `ConfigAttribute`。`support(Class)` 是由安全拦截器调用，以确保 `AccessDecisionManager` 支持安全拦截器将传入的安全对象类型。



**Voting-Based AccessDecisionManager Implementation**

同时，用户们可以实现他们自己的 `AccessDecisionManager` 来控制认证的所有方面，Spring Security 包含一些基于投票的 `AccessDecisionManager` 实现 [Figure 11.1, “Voting Decision Manager”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#authz-access-voting) 展示了相关的类：

**Figure 11.1. Voting Decision Manager**

![access-decision-voting](C:\Users\lrk\Desktop\access-decision-voting.png)

使用这种方式，一系列的 `AccessDecisionVoter` 将在授权决策轮训中被调用。然后，`AccessDecisionManager` 再根据它对投票的评估决定是否要抛出一个 `AccessDeniedException`。

`AccessDecisionVoter` 接口有以下三个方法：

```Java
int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attrs);

boolean supports(ConfigAttribute attribute);

boolean supports(Class clazz);
```

具体的实现返回一个 int，它的可能值在 `AccessDecisionManager` 中的静态字段，`ACCESS_ABSTAIN`，`ACCESS_DENIED` 和 `ACCESS_GRANTED`。一个投票实现会返回 `ACCESS_ABSTAIN`，前提是对这次授权结果没有意见。如果有意见，那么返回必须是 `ACCESS_DENIED` 或者 `ACCESS_GRANTED`。

Spring Security 提供了三种具体的 `AccessDEcisionManager`， 带有记票结果的。`ConsensusBased` 实现会基于非齐全投票共识，赋予访问权，或拒绝访问。有属性会被提供用来控制投票是平等的还是无效的。`AffirmativeBased` 实现会赋予访问权，如果一个或多个 `ACCESS_GRANTED` 投票被接收到（比如，一个拒绝票会被拒绝，至少一个赋予票）。像 `ConsensusBased` 实现，有一个参数可以控制所有投票都是弃票时的行为。`UnanimousBased` provider 期待一致的 `ACCESS_GRANTED` 投票，为了赋予访问权，忽视弃票。如果有任何的 `ACCESS_DENIED` 票，都会拒绝访问。像其他实现，这里有一个参数控制所有票都是弃权票时的行为。

实现一个自定义的 `AccessDecisionManager` 的实现是有可能的，来以不同的方式得票。比如说，从一个特殊的 `AccessDecisionVoter` 投出的票，可能会有额外的权重，同时，从一个特殊投票者投出的拒绝票有否定的效果。



**RoleVoter**

Spring Security 提供的最常使用的 `AccessDecisionVoter` 是一个简单的 `RoleVoter`，会被配置的属性当成一个简单的角色名，当用户拥有这个角色时，就投出允许票。

如果任何 `ConfigAttribute` 以 `ROLE_` 前缀开始，它都会投票。如果一个 `GrantedAuthority` 返回的 `String` 代表（通过 `getAuthority()` 方法）和一个或多个以 `ROLE_` 为前缀的 `ConfigAttributes` 完全相同，那么它就会投出允许票。如果对任意以 `ROLE_` 为前缀的 `ConfigAttribute`都没有完全符合，那么 `RoleVoter` 会投出拒绝访问。如果没有以 `ROLE_` 为前缀的 `ConfigAttributes` ，那么会投出弃权票。

**AuthenticatedVoter**

我们隐式看到的另一个投票者是 `AuthenticatedVoter`，用来区分不同的匿名者，全授权的用户，还是 remember-me 授权用户。许多站点对 remember-me 认证的用户给予了特定权限，但是多余全部权限需要用户通过登录来认证他们的身份。

但我们使用 `IS_AUTHENTICATED_ANONYMOUSLY` 属性来给匿名者赋予权限时，这个属性会被 `AuthenticatedVoter` 处理。查看这个类的 JavaDoc 来获取更多的信息。



**自定义 Voters**

显然，你可以实现一个自定义的 `AccessDecisionVoter`，然后你可以放入你希望的任何权限控制逻辑。这可能对于你的应用时特制的（业务逻辑相关），或者只是实现了一些安全管理逻辑。比如说，你可以找到一个 [blog article](https://spring.io/blog/2009/01/03/spring-security-customization-part-2-adjusting-secured-session-in-real-time) ，Spring web 站点上有很多，描述怎么使用投票者来实时拒绝一个账号被禁用的用户的访问。



##### 11.1.3 调用后处理

同时，`AccessDecisionManager` 会在安全对象被调用之前，由 `AbstrctSecurityInterceptor` 调用，一些应用需要一种方式来修改安全对象调用之后实际返回的对象。同时，你可简单地实现你自己的 AOP 来实现这一点，Spring Security 提供了一种方便的 hook，它有几个具体功能与 ACL 能力集成。

[Figure 11.2, “After Invocation Implementation”](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#authz-after-invocation) 展示了 Spring Security 的 `AfterInvocationManager` 和他的具体实现。

**Figure 11.2. After Invocation Implementation**

![after-invocation](C:\Users\lrk\Desktop\after-invocation.png)

就像许多 Spring Security 的其他部分一样，`AfterInvocationManager` 有一个单独的具体实现，`AfterInvocationProviderManager`，他带出一个列表的 `AfterInvocationProvider`。每一个 `AfterInvocationProvider` 都被允许修改返回的对象，或者抛出一个 `AccessDeniedException`。确实有很多个 providers 可以修改这个对象，前一个修改的结果会传给列表中的下一个。

请理解，如果你正在使用 `AfterInvocationManager`，你仍旧需要配置允许 `MethodSecurityInterceptor` 的 `AccessDecisionManager` 来执行这个操作的属性。如果正在使用常用的 Spring Security，包括 `AccessDeniedManager` 实现，如果没有配置属性来拒绝一个特定的安全方法调用，那么这会造成每一个 `AccessDecisionVoter` 投出弃权票。反过来，如果 `AccessDecisionManager` 的属性 "allowifAllAbstainDecisions" 是 false，一个 `AccessDeniedException` 会被抛出。你可能需要避免潜在的问题，（1）设置 “allowIfAllDecision” 为 `true`（尽管，这通常是不推荐的），或者，（2）简单地确保至少有一个属性会导致 `AccessDecisionVoter` 会投票赋予权限。后者（推荐的）方式，通常是通过一个 `ROLE_USER` 或者 `ROLE_AUTHENTICATED` 配置属性来完成的。



#### 11.1.4 分层角色

 一个应用中的特殊角色能够自动 “包含” 其他角色是一个常见需求。比如说，一个应用中，有 “admin” 和 "user" 角色，你可能希望一个 admin 能够做任何通常角色都可以做的事情。为了达到这个目标，你可以使所有的 admin 用户都被分配了通常角色。另外，你也可以修改任何访问限制，以前需要 ”user“ 角色的，现在也可以是 “admin” 角色。如果在你的应用中有一大堆的角色，那么这可能就会变得很困难。

role-hierarchy 的使用允许你去配置哪一个角色（或者 authorities）应该包含其他的。一个扩展版本的 Spring Security 的 RoleVoter，`RoleHierarchyVoter` ，和一个 `RoleHierarchy` 一起配置，从中可以获取所有的 “可达 authorities” ，也就是用户被分配的。一个典型的配置可能会像下面这样：

```XML
<bean id="roleVoter" class="org.springframework.security.access.vote.RoleHierarchyVoter">
    <constructor-arg ref="roleHierarchy" />
</bean>
<bean id="roleHierarchy"
        class="org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl">
    <property name="hierarchy">
        <value>
            ROLE_ADMIN > ROLE_STAFF
            ROLE_STAFF > ROLE_USER
            ROLE_USER > ROLE_GUEST
        </value>
    </property>
</bean>
```

这里我们有四个角色在层级中，`ROLE_ADMIN => ROLE_STAFF => ROLE_USER => ROLE_GUEST`。一个被 `ROLE_ADMIN` 授权的用户，会表现地像拥有其他四个角色一样。当安全限制被一个 `AccessDecisionManager` 配置的 `RoleHierarchyVoter` 检查时。`>` 符号可以认为是 “包含“ 的意思。

角色层级提供了一种方便的方式来为你的应用简化访问控制数据，并在你需要给用户分配时减少 authorities 的数量。为更复杂的需求，你可能希望去定义一个逻辑映射，来映射应用要求的特殊访问权限和需要赋予用户的角色，并在加载用户信息时可以互相转换。



#### 11.2 安全对象实现



#### 11.2.1 AOP Alliance （MethodInvocation） Security Interceptor

在 Spring Security 2.0 之前，确保 `MethodInvocation` 需要大量的 boiler plate 配置。现在保护方法安全的推荐方式是使用命名空间配置。这种方式方法安全基础 bean 会为你自动配置，所以你不需要真正地需要知道实现类。我们只需要提供对涉及的类的快速浏览就可以了。

使用 `MethodSecurityInterceptor` 强制保护方法，它保护了 `MethodInvocation`。取决于配置方式，一个拦截器会被确定为一个单独的 bean，或在多个 bean 之间共享。拦截器使用一个 `MethodSecurityMetasataSource` 实例来获取配置属性，这会应用到一个特定的方法调用上。 `MapBasedMethodSource` 被用来存储以方法名（可以使用通配符）为key的配置属性，并且在内部使用，当应用上下文使用 `<intercept-methods>` 和 `<protect-point>` 属性定义这些属性时。另一个实现会被用来基于注解的配置。



**明确 MethodSecurityInterceptor 配置**

你当然可以直接配置一个 `MethodSecurityInterceptor` 在你的应用上下文中，为了使用 Spring AOP 的代理机制：

```XML
<bean id="bankManagerSecurity" class=
    "org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="accessDecisionManager"/>
<property name="afterInvocationManager" ref="afterInvocationManager"/>
<property name="securityMetadataSource">
    <sec:method-security-metadata-source>
    <sec:protect method="com.mycompany.BankManager.delete*" access="ROLE_SUPERVISOR"/>
    <sec:protect method="com.mycompany.BankManager.getBalance" access="ROLE_TELLER,ROLE_SUPERVISOR"/>
    </sec:method-security-metadata-source>
</property>
</bean>
```



##### 11.2.2 AspectJ（JoinPoint） Security Interceptor

AspectJ 安全拦截器和在之前章节讨论过的 AOP Alliance 安全拦截器很相似。因此，我们在这一章节只讨论他们的不同。

AspectJ 拦截器的名字是 `AspectJSecurityInterceptor`。不像 AOP Alliance 安全拦截器，依赖于 Spring 应用上下文通过代理来将安全拦截器织入，`AspectJSecurityInterceptor` 是通过 AspectJ 编译器织入的。在一个应用中两种类型的安全拦截器一起使用是不常见的，`AspectJSecurityInterceptor` 用来领域对象实例安全，AOP Alliance `MethodSecurityInterceptor` 用在服务层的安全。

首先，我们看下 `AspectJSecurityInterceptor` 是怎么在 Spring 应用上下文中配置的：

```XML
<bean id="bankManagerSecurity" class=
    "org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor">
<property name="authenticationManager" ref="authenticationManager"/>
<property name="accessDecisionManager" ref="accessDecisionManager"/>
<property name="afterInvocationManager" ref="afterInvocationManager"/>
<property name="securityMetadataSource">
    <sec:method-security-metadata-source>
    <sec:protect method="com.mycompany.BankManager.delete*" access="ROLE_SUPERVISOR"/>
    <sec:protect method="com.mycompany.BankManager.getBalance" access="ROLE_TELLER,ROLE_SUPERVISOR"/>
    </sec:method-security-metadata-source>
</property>
</bean>
```

正如你可以看到的，除了类名之外，`AspectJSecurityInterceptor` 和 AOP Alliance 安全拦截器是完全一样的。确实，两个拦截器可以共享同一个 `securityMetadataSource`，如同 `SecurityMetadataSource` 和 `java.lang.reflect.Method` 一起工作，而不是和 AOP 库特定的类。当然，你的访问决定可以调用 特定类库（如同，`MethodInvocation` 或者 `JoinPoint`），并决定作出是否允许访问的决定（比如，方法参数）时可以考虑一系列的额外标准。

下一步，你需要定义一个 AspectJ `aspect`。比如说，

```Java
package org.springframework.security.samples.aspectj;

import org.springframework.security.access.intercept.aspectj.AspectJSecurityInterceptor;
import org.springframework.security.access.intercept.aspectj.AspectJCallback;
import org.springframework.beans.factory.InitializingBean;

public aspect DomainObjectInstanceSecurityAspect implements InitializingBean {

    private AspectJSecurityInterceptor securityInterceptor;

    pointcut domainObjectInstanceExecution(): target(PersistableEntity)
        && execution(public * *(..)) && !within(DomainObjectInstanceSecurityAspect);

    Object around(): domainObjectInstanceExecution() {
        if (this.securityInterceptor == null) {
            return proceed();
        }

        AspectJCallback callback = new AspectJCallback() {
            public Object proceedWithObject() {
                return proceed();
            }
        };

        return this.securityInterceptor.invoke(thisJoinPoint, callback);
    }

    public AspectJSecurityInterceptor getSecurityInterceptor() {
        return securityInterceptor;
    }

    public void setSecurityInterceptor(AspectJSecurityInterceptor securityInterceptor) {
        this.securityInterceptor = securityInterceptor;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.securityInterceptor == null)
            throw new IllegalArgumentException("securityInterceptor required");
        }
    }
}
```

在上面的举例中，安全拦截器可以应用到每一个 `PersistableEntity`实例上，这是一个不展示的抽象类（你可以使用另外的类或者其他你喜欢的 `pointcut` 表达式）。对于那些感兴趣的人，`AspectJCallback` 是需要的，`proceed();` 语句是有在 `around()` 方法体重才有特殊的意义。`AspectJSecurityInterceptor` 调用这个匿名 `AspectJCallback` 类，当它希望目标组件继续执行时。

你会需要配置 Spring 来加载 切片（aspect），并把它与 `AspectJSecurityInterceptor` 连接在一起。一个可以完成这个目的的 bean 声明可以是如下所示：

```XML
<bean id="domainObjectInstanceSecurityAspect"
    class="security.samples.aspectj.DomainObjectInstanceSecurityAspect"
    factory-method="aspectOf">
<property name="securityInterceptor" ref="bankManagerSecurity"/>
</bean>
```

就是它！现在你可以在应用的任何地方配置你自己的 bean，使用任何你喜欢的方式（比如，`new Persion()`），而且他们会有安全拦截器应用上来。



#### 11.3 基于表达式的访问控制

Spring Security 3.0 提供了使用 Spring EL 表达式作为一个认证机制，而配置属性和访问决策投票的简单使用，我们已经在前面看到过了。基于表达式的访问控制时在相同的结构上架构的，但是允许复杂的 是/否 逻辑包含在一个表达式中。



##### 11.3.1 总览

Spring Security 使用 Spring EL 提供表达式支持，如果你对这一点想要理解的更深刻，可以去看一下相关内容。表达式是和一个 "root object" 作为计算上下文的一部分，进行计算的。Spring Security 为 web 和 方法安全使用特定的类，作为 root object，为了提供内容部的表达式和访问诸如当前 principal 之类的值。



**常见内置表达式**

表达式 root object 的基础类是 `SecurityExpressionRoot`。这里提供了一些常见的表达式，这些都是在 web 和方法安全里通用的。

**Table 11.1. Common built-in expressions**

| Expression                                                   | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `hasRole([role])`                                            | Returns `true` if the current principal has the specified role. By default if the supplied role does not start with 'ROLE_' it will be added. This can be customized by modifying the `defaultRolePrefix` on `DefaultWebSecurityExpressionHandler`. |
| `hasAnyRole([role1,role2])`                                  | Returns `true` if the current principal has any of the supplied roles (given as a comma-separated list of strings). By default if the supplied role does not start with 'ROLE_' it will be added. This can be customized by modifying the `defaultRolePrefix` on `DefaultWebSecurityExpressionHandler`. |
| `hasAuthority([authority])`                                  | Returns `true` if the current principal has the specified authority. |
| `hasAnyAuthority([authority1,authority2])`                   | Returns `true` if the current principal has any of the supplied authorities (given as a comma-separated list of strings) |
| `principal`                                                  | Allows direct access to the principal object representing the current user |
| `authentication`                                             | Allows direct access to the current `Authentication` object obtained from the `SecurityContext` |
| `permitAll`                                                  | Always evaluates to `true`                                   |
| `denyAll`                                                    | Always evaluates to `false`                                  |
| `isAnonymous()`                                              | Returns `true` if the current principal is an anonymous user |
| `isRememberMe()`                                             | Returns `true` if the current principal is a remember-me user |
| `isAuthenticated()`                                          | Returns `true` if the user is not anonymous                  |
| `isFullyAuthenticated()`                                     | Returns `true` if the user is not an anonymous or a remember-me user |
| `hasPermission(Object target, Object permission)`            | Returns `true` if the user has access to the provided target for the given permission. For example, `hasPermission(domainObject, 'read')` |
| `hasPermission(Object targetId, String targetType, Object permission)` | Returns `true` if the user has access to the provided target for the given permission. For example, `hasPermission(1, 'com.example.domain.Message', 'read')` |





##### 11.3.2 Web 安全表达式

为了使用表达式来保护你的个人网站安全，你首先需要将 `<http>` 的 `<use-expression>` 设置为 `true`。Spring Security 就会了解 `<intercept-url>` 的 `access` 属性可能会包含 Spring EL 表达式。这个表达式的运算结果应该是 Boolean 类型，决定这个访问是否应该被允许。比如说：

```XML
<http>
    <intercept-url pattern="/admin*"
        access="hasRole('admin') and hasIpAddress('192.168.1.0/24')"/>
    ...
</http>
```

这里我们已经定义了应用中的 "admin" 区域（用 URL pattern 定义） ，应该只对拥有 "admin" 权限的用户和 URL 匹配本地子网的用户有效。我们已经看过了内置的 `hasRole` 表达式在上一章节。`hasIpAddress` 表达式是另一个内置的表达式，它是 web 安全特定的。它定义在 `WebSecurityExpressionRoot` 类中定义，它在进行 web 访问表达式计算时，被当做表达式 root object。这个对象还只在 `request` 直接暴露了 `HttpServletRequest` 对象，这样你就可以在表达式中直接调用请求。如果表达式被使用，`WebExpressionVoter` 会被增加到 `AccessDecisionManager` 中，前者被命名空间使用。所以，如果你不使用命名空间，但是希望使用表达式，你将不得不把这其中的这个添加到你的配置中。



**在安全表达式中引用 beans**

如果你希望扩展表达式，这是可能的，你可以简单地引用任何你暴露的 bean。比如说，假设你已经有一个名字是 `webSecurity` 的 bean，它包含以下的方法签名：

```Java
public class WebSecurity {
        public boolean check(Authentication authentication, HttpServletRequest request) {
                ...
        }
}
```

你可以这样引用这个方法：

```XML
<http>
    <intercept-url pattern="/user/**"
        access="@webSecurity.check(authentication,request)"/>
    ...
</http>
```

或者使用 Java 配置：

```Java
http
        .authorizeRequests()
                .antMatchers("/user/**").access("@webSecurity.check(authentication,request)")
                ...
```



**Web 安全表达式中的路径参数**

有时，能够引用 URL 中的路径参数是件很 nice 的事。比如说，考虑一个 RESTful 应用，通过 URL 路径来查询用户的 id，`/user/{userId}`。

你可以简答地通过将它放置在 pattern 中来引用这个路径参数。比如说，如果有一个名字是 `webSecurity` 的 bean，它包含以下的方法签名：

```Java
public class WebSecurity {
        public boolean checkUserId(Authentication authentication, int id) {
                ...
        }
}
```

你可以使用以下方式引用这个方法：

```XML
<http>
    <intercept-url pattern="/user/{userId}/**"
        access="@webSecurity.checkUserId(authentication,#userId)"/>
    ...
</http>
```

或者 Java 配置方式：

```Java
http
        .authorizeRequests()
                .antMatchers("/user/{userId}/**").access("@webSecurity.checkUserId(authentication,#userId)")
                ...
```

全部两种配置的 URL ，如果匹配上了，都会传递路径参数（而且转义它）给 `checUserId(Authentication authentication, int id)` 方法。比如，如果 URL 是 `/user/123/resource`，那么传递的 id 是 `123`。



##### 11.3.3 方法安全表达式

方法安全比简单地允许或拒绝规则复杂一些。Spring Security 3.0 引入了一些新的注解，为了对表达式使用的全面支持。



**@Pre 和 @Post 注解**

这里有四个注解都支持表达式属性来允许前/后调用认证检查，以及支持过滤传入的集合参数或者返回值。这些注解是 `@PreAuthorize`，`@PreFilter`，`@PostAuthorize` 和 `@PostFilter`。他们通过命名空间的 `global-method-security` 来使能。

```XML
<global-method-security pre-post-annotations="enabled"/>
```



**使用 @PreAuthorize 和 @ PostAuthorize 来进行访问权限控制**

最常见的注解是 `@PreAuthorize`，它决定一个方式是否可以被调用。举例来说，（来自于 “Contacts” 示例）

```Java
@PreAuthorize("hasRole('USER')")
public void create(Contact contact);
```

这意味着只有 `ROLE_USER` 角色的用户才允许访问。显然，相同的事情可以通过传统的配置，以及一个简单的配置属性指定需要的角色。但是，这样写：

```Java
@PreAuthorize("hasPermission(#contact, 'admin')")
public void deletePermission(Contact contact, Sid recipient, Permission permission);
```

这里，我们实际使用了方法参数作为表达式的一部分来决定当前用户对当前给定的连接，的是否拥有 “admin” 允许。内置的 `hasPermission()` 表达式通过 Spring 应用上下文连接进 Spring Security ACL 模块，正如我们将在下面看到的。你可以通过名字访问任何的方法参数，作为表达式的变量。

Spring Security 中有许多方式可以解析参数。Spring Security 使用 `DefaultSecurityParameterDiscover` 来检测方法名。默认下，对整个方法尝试一下的方法：

* 如果 Spring Security 的 `@P` 注解出现在方法的单独一个参数上时，这个值就会被使用。这对 JDK 8之前的接口编译是很有用的，因为这之前编译出来并不会包含任何与参数名相关的信息。比如说：

  ```Java
  import org.springframework.security.access.method.P;
  
  ...
  
  @PreAuthorize("#c.name == authentication.name")
  public void doSomething(@P("c") Contact contact);
  ```

  这个场景背后，它使用了 `AnnotationParameterNameDiscoverer` ，它可以自定义来支持任何特定的值属性。

* 如果 Spring Data 的 `@Param` 注解出现在至少一个方法参数上，这个值就会被使用。这对 JDK 8之前的接口编译是很有用的，因为这之前编译出来并不会包含任何与参数名相关的信息。比如说：

  ```Java
  import org.springframework.data.repository.query.Param;
  
  ...
  
  @PreAuthorize("#n == authentication.name")
  Contact findContactByName(@Param("n") String name);
  ```

  这个场景背后，它使用了 `AnnotationParameterNameDiscoverer`,它可以自定义来支持任何特定的值属性。

* 如果使用了 JDK 8 来编译源码，并带上 `-parameter` 参数，而且使用了 Spring 4+，那么标准的 JDK 反射 API 可以被用来检测参数名。这对类和接口同样适用。

* 最后，如果代码带上了调试符号下编译，那么参数名可以用调试符号检测到。因为接口不包含任何关于方法参数的 debug 信息，所以他们不会有作用。对于接口，注解或者 JDK 8 方式是必须的。

任何 Spring EL 功能在表达式内是有效的，所以你也可以访问参数的属性。比如，如果你希望一个特别的方法来允许访问一个用户，名字和协议相符合，你可以这样写：

```Java
@PreAuthorize("#contact.name == authentication.name")
public void doSomething(Contact contact);
```

这里，我们访问了另一个内置的表达式，`authentication`，这是 `Authentication` 存储在安全上下文中。你也可以直接访问它的 “principal” 属性，使用表达式 `principal`。这个值经常会是一个 `UserDetails` 示例，所以你可能使用一个类似 `principal.username` 的表达式，或者 `principal.enable`。

不太常见的，你可能希望执行一个访问控制检查，在方法被调用之后。这可以通过 `@PostAuthorize` 注解来完成。为了访问一个方法的返回值，可以在表达式中使用内置的名字 `returnObject` 。



**使用 @PreFilter 和 @PostFilter 过滤**

正如你已经知道的，Spring Security 支持集合和数组的过滤，这可以使用表达式完成。最常见的方式是在方法的返回值上。比如说：

```Java
@PreAuthorize("hasRole('USER')")
@PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, 'admin')")
public List<Contact> getAll();
```

 当使用 `@PostFilter` 注解，Spring Security 通过迭代返回的集合，并移除任何应用表达式之后为 false 的成员。`filterObject` 这个名字引用了集合中的当前对象。你可以在方法调用之前进行过滤，使用 `@PreFilter`，尽管这是一个不怎么常见的需求。语法是相同的，但是如果这里又不止一个参数是集合类型，你不得不使用注解的 `filterTarget` 属性，来通过名字去选择。

注意这一点，过滤器显然不适用于调整数据检索。如果你正在过滤一个大集合，并且移除大部分的属性，那么这很可能是低效的。

  

**内置表达式**

有一些内置表达式，是针对方法安全的，我们在之前已经见过了。`filterTarget` 和 `returnValue` 值是足够简单的，但是 `hasPermission()` 表达式的使用也值得仔细研究。



**PermissionEvaluator 接口**

`hasPermission()` 表达式被委托给一个 `PermissionEvaluator` 实例。这意图在表达式系统和 Spring Security 的 ACL 系统之间进行桥接，允许你指定在领域对象上指定认证限制，基于抽象许可。在 ACL 模型上，它没有明确的依赖，所以你可以在需要的时候把它换成另一个实现。这个接口，有两个方法：

```Java
boolean hasPermission(Authentication authentication, Object targetDomainObject,
                            Object permission);

boolean hasPermission(Authentication authentication, Serializable targetId,
                            String targetType, Object permission);
```

它直接映射到表达式的可应用版本，并在第一个参数（`Authentication` 对象）没有应用时抛出异常。第一个方法的使用场景是领域对象，访问是受控制的，已经被加载时候。然后表达式会在当前用户拥有权限访问给定的对象时，返回 true。第二个版本是在对象没有被加载时使用的，但是它的标识符是已知的。领域对象的抽象 “type” 符号也是需要的，允许当前的 ACL 许可被加载。这在传统上需要是一个 Java bean，但也不一定，只要与许可加载的方式一致即可。

为了使用 `hasPermission()` 表达式，你不得不精确配置一个 `PermissionEvaluator` 在你的应用上下文中。这看上去会像是：

```Java
<security:global-method-security pre-post-annotations="enabled">
<security:expression-handler ref="expressionHandler"/>
</security:global-method-security>

<bean id="expressionHandler" class=
"org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler">
    <property name="permissionEvaluator" ref="myPermissionEvaluator"/>
</bean>
```

这里，`myPermissionEvaluator` 是一个实现了 `PermissionEvaluator` 接口的 bean。通常，这会是来自 ACL 模型的实现，即，`AclPermissionEvaluator`。查看 “Contacts” 示例的程序配置来获取更多细节。



**方法安全元注解**

你可以使用元注解来完成方法安全，以增强你的程序的可读性。这是非常方便的，如果你发现你正在你的代码中重复着复杂的表达式。比如说，考虑以下的内容：

```Java
@PreAuthorize("#contact.name == authentication.name")
```

与其在各处重复这个表达式，我们可以创造一个可以替代它的元注解：

```Java
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("#contact.name == authentication.name")
public @interface ContactPermission {}
```

元注解可以被任何 Spring Security 方法安全注解使用。为了保持符合规范，JSR-250注释不支持元注释。