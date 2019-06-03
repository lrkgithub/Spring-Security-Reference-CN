#### 8 架构与实现

熟悉了如何设置和运行一些基于命名空间配置的应用，你可能希望了解更多在命名空间表象背后的框架工作方式。像大多数软件，Spring Security 有某些中心接口，类和抽象概念，贯穿了整个框架。在参考手册的这一部分，我们会关注部分的核心内容，来观察它们是如何一起使 Spring Security 完成认证和准入控制。



#### 8.1 技术概述



##### 8.1.1 运行时环境

Spring Security 3.0 需要 Java 5.0 Runtime Environment 或更高。由于 Spring Security 旨在独立方式运行，因此无需将任何配置文件放入你的 Java Runtime Environment 。所以，没有必要配置一个特别的 Java Authentication and Authorization Service （JAAS）策略文件，或把 Spring Security 放入 classpath 路径下。

类似的，如果你使用 EJB 容器或 Servlet Container，没有必要放入任何特殊的配置文件到任何位置，也不需要把 Spring Security 放入服务器 classloader 中。所有需要的文件都会被包含在你的应用中。

这种提供了最大程度的部署时间灵活性，因为你可以简单地拷贝你的目标文件（一个 JAR，WAR 或 EAR），从一个系统到另一个，它就会立即工作。



##### 8.1.2 核心组件

在 Spring Security 3.0，`spring-core-security.jar` 被剥离到最低限度。它不再包含任何与 web 应用安全相关的代码，例如，LDAP， 或者命名空间配置。我们会先看一眼一些在核心模块中能找到的 Java 类型。他们代表了框架的构建基础，如果你需要深入到简单命名空间配置背后的原理，所以你能理解这些构建基础是很重要的，即便你现在不实际需要和他们直接交互。



**SecurityContextHolder，SecurityContext and Authentication Objects**

最基本的对象是 `SecurityContextHolder` 。这是我们存储应用的当前安全上下文的位置，这包含了当前使用该应用程序的主要细节。 `SecurityContextHolder` 默认使用了 `ThreadLocal` 来存储这些细节，这意味着在同一个执行线程中，安全上下文对方法总是可用的，即使它没有被作为参数显式传递。如果考虑到当前请求主体结束之后，需要清理线程，那么以这种方式使用 `ThreadLock` 是一个安全的方式。那么，Spring Security 自动帮你解决这个问题，所以没有必要去担心这一点。

一些应用使用 `ThreadLocal` 不是十分合适，因为他们需要与线程工作的特殊方式。举例来说，一个 Swing 客户端可能需要 Java Virtual Machine 中的所有线程来使用安全上下文。`SecurityContextHolder` 在启动时可以配置如何存储上下文的策略。对于一个独立的应用，你应该会用 `SecurityContextHolder.MODE_GLOBAL` 策略。其他应用可能希望有安全线程生成的线程也是用同样的安全标志。这通过 `SecurityContextHolder.MODE_INHERITABLETHREADLOCAL` 可以实现。你可以通过两种方式来改变默认的 `SecurityContextHolder_THREADLOCAL` 模式。第一种是设置系统变量，另一种是调用 `SecurityConextHolder` 的一个静态方法。大多数应用不需要改变默认模式，但如果需要，通过阅读 `SecurityContextHolder` 的 JavaDoc 。



**从当前用户中获取信息**

在 `SecurityContextHolder` 中，我们存储与当前应用交互的主体细节信息。 Spring Security 使用一个 `Authentication` 对象来代表信息。通常不需要手动创建一个 `Authentication` ，但是查询 `Authentication` 是十分常用的。你可以使用下面的代码块 - 在你代码中的任意位置 - 来获取目前已验证用户的名字，例如：

```java
Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

if (principal instanceof UserDetails) {
String username = ((UserDetails)principal).getUsername();
} else {
String username = principal.toString();
}
```

这个对象（SecurityContext）可以通过调用 `getContext()` 方法来获取一个 `SecurityContext` 接口的实例。这就是存在线程本地缓存（thread-local storage）中的对象。正如我们要在下面看到的， Spring Security 的绝大多数验证机制都会返回一个 `UserDetails` 实例作为实体。



**The UserDetailsService**

另一项可以从上述代码片段的信息是，你可以从 `Authentication` 对象中获取 principal 。所谓的 principal 只是一个 `object` 。大多数时候，这可以被强转为 `UserDetails` 对象。`UserDetails` 是 Spring Security 的一个核心接口。它代表了一个 principal ，但是是以一种可扩展和应用特定的方式。可以把 `UserDetails` 视作你的用户数据库与 `SecurityContextHolder` 中 Spring Security 需要的内容之间的适配器。`UserDetails`作为用户数据库中信息的子集，你经常会把它强转为你的应用提供的实际类对象，并调用业务相关的方法，例如，`getEmail()` ，`getEmployNumber()` ，以及其他的。

到现在为止，你可能还在思考，那什么时候我提供了一个 `UserDetails` 对象？我是怎么做到的？我以为你说的这个东西是声明的，不需要写任何代码 - 谁给出的呢？简单的回答就是有一个特别的接口叫做 `UserDetailsService` 。这个接口中的唯一方法接受一个 `String` 类型的用户名参数，并返回一个 `UserDetails` 。

```java
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```

这是最常用的在 Spring Security 中载入一个用户信息的方式，你将会看到这个方式贯穿整个框架，在任意需要用户信息的时刻都使用。

在成功认证之后，`UserDetails` 被用来构建存储在 `SecurityContextHolder` 中的 `Authentication` 对象（详情在下文）。好消息是我们提供了一系列的 `UserDetailsService` 实现，包括一个使用了内存 map（`InMemoryDaoImpl`）和另一个使用了 JDBC（`jdbcDaoImpl`）的实现。大多数用户倾向于自己编写一个实现类，基于代表员工，客户，或其他使用者的数据访问对象（Data Access Object，DAO）上。记住我们的优势，无论你的 `UserDetailsService` 返回什么，我们都可以使用前面的代码片段从 `SecurityContextholder` 中获取。

> 对于 `UserDetailsService` 有一些常见的误解。这只是一个获取用户数据的 DAO 对象，功能仅仅是将这些数据获取出来后传递给框架中的其他组件。 特别地，它不认证用户，认证是由 `AuthenticationManager` 来完成的。很多情景下，如果你需要定义身份认证过程，直接实现 `AuthenticationProvider` 接口会更有意义。



**GrantedAuthority**

除了 principal ，`Authentication` 提供的另一个重要的方法是 `getAuthorities()`。这个方法提供了一个 `GrantedAuthority` 对象的数组。毫无疑问地， `GrantedAuthority` 是授予 principal 的权限。这些权限通常是角色，例如，`ROLE_ADMINISTRATOR` 或者 `ROLE_HR_SUPERVISOR` 。稍后，会为 web 授权，方法授权，域对象授权配置这些角色。Spring Security 的其他部分能够解读这些权限，并且期待他们存在。`GrantedAuthority` 通常是由 `UserDetailsService` 载入的。

通常，`GrantedAuthority` 是应用范围的许可。他们对任意给定的域对象是一样的。因此，你不太可能让一个 45 号员工获取一个 `GrantedAuthority` ，因为如果有上千个这样的权限的话，你的内存很快就耗尽了（或者，至少，会导致应用花费很长的时间来认证一个用户）。当然，Spring Security 是被专门设计用来处理这个常见需求的，但你可以使用项目的域安全对象安全能力来完成这个目的。



**总结**

回顾一下，我们见过的 Spring Security 的主要构建模块时：

* `SecurityContextHolder`，用来获取 `SecurityContext` 
* `SecurityContext`，持有 `Authentication` ，可能还有特定请求的安全信息
* `Authentication`，代表 Spring Security 特定方式的 principal
* `GrantedAuthority`，反映了应用范围内，给 principal 的授权
* `UserDetails`，从你的应用的 DAOs 或其他安全数据源提供必要信息来构建 Authentication
* `UserDetailsService`，传入一个 `String` 类型的用户名（或认证 ID，等其他）后，新建一个 `UserDetails` 对象。

现在，你对这些重读使用的组件有了一定认识，我们可以对认证过程仔细研究一下。



##### 8.1.3 Authentication

Spring Security 可以参与许多不同的认证环境。虽然我们建议人们使用 Spring Security 来认证，而且不要与已存在的 Container Managed Authentication 集成，尽管这是受支持的 - 与你自己的身份认证系统集成。



**Spring Security 中的认证是什么？**

我们考虑一下大家都熟悉的认证场景：

1. 一个用户提供用户名和密码，尝试登陆
2. 系统认证（成功地）密码与用户名是匹配的
3. 获取到用户的上下文信息（用户的角色列表，以及其他）
4. 为用户存在的安全上下文
5. 用户继续操作，可能执行了一下需要访问控制机制保护的操作，那么访问控制机制就会针对当前的安全上下文来检查用户被许可执行

前三项构成了身份认证过程，所以我们将了解一下在 Spring Security 中这三项是怎么发生：

1. 用户名和密码会被获取并且保定存入 `UsernamePasswordAuthenticationToken` 中（`Authentication` 接口的一个实现，之前见过）
2. token 被传给 `AuthenticationManager` 进行认证
3. `AuthentcationManager` 在认证成功后返回一个填充满信息的 `Authentication` 实例
4. 通过将返回的认证对象传入 `SecurityContextHolder.getContext().setAuthentication(...)` 来建立一个安全上下文

从此以后，就认为这个用户是被授权了的。我们看一下代码，作为一个示例

```java
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

public class AuthenticationExample {
    private static AuthenticationManager am = new SampleAuthenticationManager();

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

        while(true) {
            System.out.println("Please enter your username:");
            String name = in.readLine();
            System.out.println("Please enter your password:");
            String password = in.readLine();
            try {
                Authentication request = new UsernamePasswordAuthenticationToken(name, password);
                Authentication result = am.authenticate(request);
                SecurityContextHolder.getContext().setAuthentication(result);
                break;
            } catch(AuthenticationException e) {
                System.out.println("Authentication failed: " + e.getMessage());
            }
        }
        System.out.println("Successfully authenticated. Security context contains: " + SecurityContextHolder.getContext().getAuthentication());
    }
}

class SampleAuthenticationManager implements AuthenticationManager {
    static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();

    static {
        AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
    }

    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        if (auth.getName().equals(auth.getCredentials())) {
            return new UsernamePasswordAuthenticationToken(auth.getName(),
                                                           auth.getCredentials(), AUTHORITIES);
        }
        throw new BadCredentialsException("Bad Credentials");
    }
}
```

我们在这里写了一个小程序，要求用户输入用户名和密码，并按上述顺序执行。我们实现的 `AuthenticationManager` 会认证任何用户名和密码一致的用户。它给所有用户赋予同一个身份。上述程序的输出将会是：

```Terminal
Please enter your username:
bob
Please enter your password:
password
Authentication failed: Bad Credentials
Please enter your username:
bob
Please enter your password:
bob
Successfully authenticated. Security context contains: \
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@441d0230: \
Principal: bob; Password: [PROTECTED]; \
Authenticated: true; Details: null; \
Granted Authorities: ROLE_USER
```

注意你通常不需要写任何这样的代码。该程序通常在内部执行，就像 web 认证过滤器。我们整理了这些代码，是为了说明在 Spring Security 中如何进行身份认证有一个很简单的回答。当 `SecurityContextHolder` 中包含一个全部填充满信息的 `Authentication` 对象。



**直接设置 SecurityContextHolder 内容**

事实上，Spring Security 并不关心你是怎么将 `Authentication` 对象存放进 `SecurityContextHolder` 中的。唯一的关键点是，`SecurityContextHolder` 在 `AbstractSecurityInterceptor` 需要授权用户操作之前，就包含了一个代表 principal 的 `Authentication` 。

你可以（很多用户也是这么做的）编写自己的过滤器或者 MVC 控制器，来提供不基于 Spring Security 的认证系统的互相操作。举例来说，你可以用 Container-Managed Authentication 来使用户对 ThreadLocal 或者 JNDI 可用。或者，你工作的公司可能有个老的专有认证系统，这你无法控制的企业”标准“。这种情景下，让 Spring Security 工作，并提供认证能力是很容易的。你需要做的全部，就是写一个过滤器（或者相同的东西），从某个地方读取第三方用户信息，构建一个 Spring Security 特有的 `Authenticatin` 对象，放入 `SecurityContextHolder` 中。这种情况下，你还需要考虑一下通常是内置认证机制所自动关心的事情。比如，你可能需要在响应返回给用户之前，创建一个 HTTP session 来保存多个请求之间的上下文。很有可能在响应回复给用户之后，就再创建一个 session 。

如果你在思考 `AuthenticationManager` 在真实例子是如何实现的，我们可以参考一下 [核心服务章节](8.2.1 The AuthenticationManager, ProviderManager and AuthenticationProvider)。



##### 8.1.4 在 Web 应用中的认证

现在，我们来探索一下你在 web 应用中使用 Spring Security 的情景（没有 `web.xml` 使能 security）。一个用户是怎样认证并且建立安全上下文的？

考虑一下典型的 web 应用的认证过程：

1. 你访问主页面，点击一个链接
2. 一个请求到达服务器，服务器决策你的请求是一个受保护的资源
3. 虽然你当前没有被认证，服务器返回一个 response 说明你必须被授权。这个 response 可以使一个 HTTP 返回码，也可以是一个重定向到另一个特定的 web 页面
4. 取决于认证机制，你的浏览器可能会导向特定的 web 页面，你可以填写表单，或者，浏览器以某种方式获取你的身份信息（通过 BASIC 认证对话框，cookie，X.509 证书等等）
5. 浏览器会将 response 返回给服务器。这可以是一个 HTTP POST 请求，包含了你填写的表单信息，或者是一个包含你的认证具体信息的 HTTP header。
6. 下一步，服务器会决定目前的证书是否是有效的。如果是有效的，就进入到下一步；如果是无效的，通常你的浏览器会要求你重试一次（那么，你返回到步骤 2）。
7. 导致的认证过程的原始请求会再次被请求。希望你使用了有足够授权的认证来获取受保护的资源。如果有足够的权限，请求将会成功。不然的话，你会收到一个 HTTP 错误码 403，代表了 “forbidden”。

Spring Security 拥有不同的类负责上述的步骤。主要的参与者（按上述被使用的顺序）是，`ExceptionTranslationFilter`，`AuthenticationEntryPonit` 和一个认证机制，负责调用 `AuthenticationManager` 就像我们之前章节看到的。



**ExceptionTranslationFilter**

`ExceptionTranslationFilter` 是一个 Spring Security 过滤器，负责处理所有 Spring Security 抛出的异常。这些异常通常是 `AbstractSecurityInterceptor` 抛出的，它是认证服务的主要提供者。下一章节，我们就会讨论 `AbstractSecurityInterceptor`，这里我们只要先知道这个类会抛出与 HTTP 无关的 Java 异常，以及它不能获取关于认证的 principal 。`ExceptionTranslationFilter` 提供对两种场景负有具体责任，当 principal 被授权但是权限不足时候，返回 HTTP 错误码 403（回到上面的步骤 7），或者是 principal 没有被授权时，加载 `AuthenticationEntryPoint` （因此，我们回到步骤 3）。



**AuthenticationEntryPoint**

`AuthenticationEntryPoint` 对上述的步骤 3 负责。正如你想象的，每一个 web 应用都有一个默认的认证策略（这些策略可以像 Spring Security 中的其他东西一样可以配置，但我们现在先从简单的开始）。每一个主要的认证系统都会有自己的 `AuthenticationEntryPoint` 实现，通常会执行步骤 3 的动作。



**认证机制**

一旦你的浏览器提交了你的认证凭据（使用 HTTP 表单提交，或者 HTTP header），在服务器端需要一些东西来“收集”认证凭据等信息。现在，我们就在步骤 6 。在 Spring Security 中，我们为从一个用户终端（通常是一个浏览器）获取认证凭据等信息的功能命名了一个特殊的名字，称之为 “认证机制”。示例就是表单登录和 Basic 认证。一旦认证凭据等信息从用户端被收集，一个 `Authentication` ”请求“ 对象就被创建了，并被传递给 `AuthenticationManager`。

在认证机制收到填充完全的 `Authentication` 对象，它就认为请求时合法的，把 `Authentication` 放入 `SecurityContextHolder` 中，并导致请求重试（步骤 7）。如果，另一方面，`AuthenticationManager` 拒绝了请求，认证机制会要求用户端重试（步骤 2）。



**在请求之间，存储 SecurityContext**

取决于应用的类型，有必要指定在用户操作之间存储安全上下文的策略。在一个典型的 web 应用中，用户一旦登录，后续就会通过会话 ID 识别。服务端会为后续会话缓存 principal 信息。在 Spring Security 中，在请求之间保存 `SecurityContext` 的任务落在了 `SecurityContextPersistenceFilter` 上，它默认会在 HTTP 请求之间，将上下文作为 `HttpSession` 属性存储。在每一次请求时，将上下文传给 `SecurityContextHolder`，并在请求完成之后，清空 `SecurityContextHolder` 。你不需要为了安全目的直接和 `HttpSession` 直接交互。没有理由这么做，直接使用 `SecurityContextHolder` 就可以了。



许多其他类型的应用（例如，一个无状态的 RESTful web 服务）不使用 HTTP session，在每次请求时都会重新认证。然而，将 `SecurityContextPersistenceFilter` 包括在调用链中，并确保在每次请求后清空 `SecurityContextHolder` 还是很重要的。

> 在一个单独会话中接受并发请求的应用，同一个 `SecurityContext` 实例会在线程间共享。即使是通过 `ThreadLocal` 来完成，每个线程获取的 `HttpSession` 也是同一个实例。如果你希望在一个线程中临时改变上下文，这也会有影响。如果你使用 `SecurityContextHolder.getContext()`，然后调用 `setAuthentication(anAuthentication)` 存放前一个方法返回的对象，那么所有并发线程中的 `Authentication` 对象都会改变，因为他们共享一个 `SecurityContext` 实例。你可以自定义 `SecurityContextPersistenceFilter` 的行为来为每一个线程创建一个新的 `SecurityContext` ，这可以保护一个线程的改变会影响另一个线程。或者，你可以在临时改变上下文的地方创建一个新的实例。 `SecurityContextHolder.createEmptyContext()` 方法永远会返回一个新的上下文实例。



##### 8.1.5 Spring Security 中的访问控制（授权）

在 Spring Security 中决策访问控制的重要接口是 `AccessDecisionManager` 。它有一个 `decide` 方法，接受一个 `Authentication` 对象，代表请求许可的 principal ，一个 “安全对象” （见下文）和一个应用对象的安全元数据属性列表（例如，请求许可需要被授予的角色列表）。



**Security 和 AOP Advice**

如果你熟悉 AOP，那么你就会知道几种不同类型的 advice ：前置，后置，抛出和环绕。一个环绕 advice 是十分有用的，因为一个 advisor 可以选择是否执行方法调用，是否修改 response ，是否抛出异常。 Spring Security  为方法调用，也就是 web 请求，提供了一个环绕 advice 。我们可以使用 Spring 标准 AOP 支持来完成方法调用，也可以使用标准 Filter 来完成 web 请求的环绕 advice 。

对于不熟悉 AOP 的人，重点是需要理解 Spring Security  会帮助你保护方法调用，也就是，web 请求。大多数人对在服务层进行安全方法调用感兴趣。这是因为，在当前版本的 Java EE 应用中，大多数业务逻辑都包括在服务层。如果你只是希望在服务层保护方法调用，那么 Spring 的标准 AOP 就适用了。如果你想要直接保护你的领域对象，你可能会发现 AspectJ 是值得考虑的。

你可以选择使用 AspectJ 或者 Spring AOP 来完成方法授权，或者选择过滤器来完成 web 请求认证。你可以任意选择其中的 0 种，1 种， 2 种，3 种方法。主流使用方法是使用一些 web 请求授权，并在服务层配合使用一些 Spring AOP 方法认证。



**Security Object 和 AbstractSecurityInterceptor**

所以，什么是一个 "Security Object" ？Spring Security 使用这个术语来描述那些可以被安全机制（例如，认证授权）保护的对象。最常见的例子就是方法调用和 web 请求。

每一个受支持的安全对象类型都有他自己的拦截器类型，这些拦截器都是 `AbstractSecurityInterceptor` 的子类。重要的是，当 `AbstractSecurityInterceptor` 被调用时，如果 principal 被授权了 ，那么`SecurityContextHolder` 会包含一个有效的 `Authentication` 。

`AbstractSecurityInterceptor` 提供了一系列的工作流，来处理安全对象请求，典型的有：

1. 寻找与当前请求相关的“配置属性”
2. 提交安全对象，当前的 `Authentication` 和配置属性到 `AccessDesicionManager` ，来完成认证决策。
3. 在调用发生时，可选地修改 `Authentication` 。
4. 允许继续执行安全对象调用（假设访被许可）
5. 如果配置了 `AfterInvocationManager` ，一旦调用返回，就调用它。如果调用导致了一个异常，`AfterInvocationManager` 就不会被调用。



**什么是配置属性？**

配置属性可以认为是对 `AbstractSecurityInterceptor` 使用的类有特殊含义的 String 。在框架中，他们被 `ConfigAttribute` 接口代表。他们可能是简单的角色名，或者有更复杂的含义，取决于 `AccessDecisionManager` 实现有多复杂。`AbstractSecurityImterceptor` 被配置了一个 `SecurityMetadataSource` 属性，后者是用来为安全对象寻找属性的。通常，这个配置对使用者是隐藏的。配置属性可以作为安全方法上的注解，或者安全 URLs 上的的访问属性输入。举例来说，当我们在命名空间看到 `<intercept-url pattern='/secure/**' access='ROLE_A,ROLE_B'/>` 这样的东西，它的意思是配置属性 `ROLE_A` 和 `ROLE_B` 应用到了符合给定的模式的 web 请求上。实践中，配合默认的 `AccessDecisiionManager` 配置，这意味着任何拥有 `GrantedAuthority` 的用户能匹配上两个属性中任意一个的，就会被准许访问。直接地说，他们只是属性，解释权属于 `AccessDecisionManager` 的具体实现。使用 `ROLE_` 前缀，说明这是一个角色属性，并且应该被 Spring Security 的 `RoleVoter` 消费。这仅在基于候选者方式的 `AccessDecisionManager` 使用是有意义。我们将在 [授权章节](11.1 授权结构) 了解 `AccessDecisionManager` 的实现。



**RunAsManager**

假设 `AccessDecisionManager` 决定允许请求访问，`AbstractSecurityInterceptor` 通常会继续执行请求。话说回来，用户在汉奸的情景下，可能需要在 `SecurityContext` 替换 `Authentication` ，这个操作会由 `AccessDecisionManager` 调用 `RunAsManager` 来完成。这在合理但不常见的场景下是很有用的，例如，如果服务层方法需要调用远程系统并呈现不同的身份。因为 Spring Security 自动将安全身份信息在不同系统间传递（假设你正在使用正确配置的 RMI 或者 HttpINvoker 远程协议客户端），所以这会很有用。



**AfterInvocationManager**

随着安全对象调用继续进行并返回 - 这可能意味着方法调用完成或者过滤器链继续进行 - `AbstractSecurityInterceptor` 得到一个最后的机会来处理调用。在这一步，`AbstractSecurityInterceptor` 可能会对修改返回对象有兴趣。在安全对象调用的中途这是不能被处理的，所以我们可能希望存在上述操作途径。作为高度可插拔， `AbstractSecurityInterceptor` 在有需要时，会把控制权交给 `AfterInvocationManager` 来真实地修改对象。这个类可以被完全替代，或者抛出异常，亦或者是改变它。after-invocation 检查只有在调用成功时才会被执行。如果，异常排除，额外的检查就会被跳过。

`AbstractSecurityInterceptor` 以及它相关的类在下图中展示。

**Figure 8.1. Security interceptor and the "security object" model**

![security-interception](C:\Users\l15598\Desktop\security-interception.png)



**扩展安全对象模型**

我们的开发者正在考虑一套全新的拦截和认证请求的方式，这需要直接使用安全对象。举例来说，可以构建一个新的安全对象来保护对信息系统的调用。能够提供安全并且能提供拦截方法（类似 AOP 围绕 advice 语义）的东西都能成为一个安全对象。但其实，Spring 应用可以简单地使用三个已经支持的完全透明的安全对象类型（AOP Aliance `MethodInvocation` ，AspectJ `JoinPonit` 和 web 请求 `FilterInvocation` ）。



##### 8.1.6 本地化

Spring Security 支持将终端用户可以看到的异常信息本地化。如果你的系统是为了英语使用者设计的，你不要做任何事情，因为 Security 信息本身就是英语写的。如果你需要支持其他的本地化，任何你需要知道的内容都在本节。

任何异常信息都可以被本地化，包括与认证失败，申请被拒绝（认证失败）相关的信息。开发人员或者系统部署人员应该关注的异常和日志信息（包含错误的属性，接口不合规，使用错误的构造器，非法的启动时间，debug 级别的日志），都不是本地化的，而是用英语硬编码在 Spring Security 中。

浏览 `spring-security-core-xx.jar` ，你会发现一个 `org.springframework.security` 包，它又包含了一个 `message.properties` 文件，以及一些其他常用语言的本地化版本。这应该被你的 `ApplicationContext` 引用，因为 Spring Security 类实现了 Spring 的 `MessageWare` 接口，并且在启动时，期待信息解析器被依赖注入到你的应用上下文。通常你需要做的是在你的应用上下文中注册一个 bean 指向那些信息。如下是一个示例：

```xml
<bean id="messageSource"
    class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
<property name="basename" value="classpath:org/springframework/security/messages"/>
</bean>
```

`messages.properties` 是根据标准资源包命名，表示 Spring 支持的默认语言。默认的文件是英文的。

如果你希望定制 `messages.properties` 文件，或者支持别的语言，你应该拷贝一份文件，相应地重命名，并在上面的 bean 定义中注册它。在文件中有大量的信息键，所以本地化不具备太多的主观能动性。如果你在这份文件中完成本地化，请考虑分享你的工作到协会记录 JIRA 任务，并附上你的正确命名的本地化版本的 `messages.properties` 。

Spring Security 依赖 Spring 的本地化支持，为了寻找到合适的信息。为了它工作起来，你必须确定来自本地的请求被存储在 Spring 的 `org.springframework.context.i18n.LocalContextHolder` 。Spring MVC 的 `DispatcherServlet` 为你的应用自动做了这件事，但是因为 Spring Security 的过滤器在这之前被调用，`LocalContextHolder` 需要在过滤器被调用之前，就设置好恰当的 `Local` 。你可以自己在你的过滤器中完成这个动作（必须在 `web.xml` 中定义的过滤器之前），或者利用 `RequestContextFilter` 。

"contacts" 示例已经为应用设置好了本地化信息。



#### 8.2 核心服务

既然我们有了一个对 Spring Security 架构和它的核心类的大致浏览，我们仔细观察一下一到两个它的核心接口以及它们的实现，尤其是 `AuthenticationManager` ，`UserDetailsService` 和 `AccessDecisionManager` 。这些会在接下来的文档中时不时出现，所以你最好知道如何配置它们， 它们又是如何工作的？



##### 8.2.1 The AuthenticationManager, ProviderManager and AuthenticationProvider

`AuthenticationManager` 只是一个接口，所以我们可以选择任意的实现，但它在实践中是如何工作的呢？如果我们需要检查多重认证数据库或者结合不同的认证服务，例如，LDAP 服务？

Spring Security 中的默认实现是 `ProviderManager` 。它并不是自己处理认证请求，而是把这个任务代理给其他一系列的配置的 `AuthenticationProvider` ，每一个按顺序检查它是否可以进行授权。每一个提供者要不就是抛出异常，不然就会返回一个被填充完整的 `Authentication` 对象。记得我们的好朋友，`UserDetails` 和 `UserDetailsService`？如果不记得的话，请返回前面的章节，重新认识一下。最常见的验证授权请求的方式是载入一个相应的 `UserDetails` ，然后检查用户输入的密码和载入的密码时候一致。这是 `DaoAuthenticationProvider` 采取的方式（见下文）。加载的 `UserDetails` 对象 - 特别是它包含的 `GrantedAuthority` - 将会在构建一个填充完整的 `Authentication` 对象时被用到。也就是成功授权后返回的，冰杯存储在 `SecurityContext` 中的对象。

如果你是用命名空间的方式创建一个 `ProviderManager` 实例，那么你可以把提供者也用命名空间的方式加入进去（查看命名空间章节）。这种情况下，你不应该申明一个 `ProviderManager` bean 在你的应用上下文中。然而，如果你不使用命名空间，你可以如下申明：

```xml
<bean id="authenticationManager"
        class="org.springframework.security.authentication.ProviderManager">
    <constructor-arg>
        <list>
            <ref local="daoAuthenticationProvider"/>
            <ref local="anonymousAuthenticationProvider"/>
            <ref local="ldapAuthenticationProvider"/>
        </list>
    </constructor-arg>
</bean>
```

在上面的例子，你可以看到三个提供者。他们按定义的顺序（会简单地用一个 `List` 实现）尝试授权给请求，或者跳过认证简单地返回一个 `null` 。你需要的请求者有时候对认证机制是通用的，而有时候会依赖于特定的认证机制。举例来说，`DaoAuthenticationProvider` 和 `LdapAuthenticationProvider` 和任何机制都是兼容的，只要这些机制提交了一对简单的用户名/密码认证请求，两个提供者也可以和基于表单的登录或者 HTTP BASIC 认证兼容。另一方面，一些认证机制提供的认证请求对象只能被某种特殊类型的 `AuthenticationProvider` 解读。你并不需要太过关心这一点，因为如果你忘记注册了合适的提供者，在尝试认证时，你会简单地收到 一个 `ProviderFoundException` 异常。



**认证成功后擦除凭证**

默认情况下（从 Spring Security 3.1 之后），`ProviderManager` 会尝试擦除任何 `Authentication` 对象中的敏感凭证信息，该对象在认证成功后会被返回。这保护了密码等信息只在有必要时才保留。

这在你使用缓存的用户对象时可能造成问题，例如，提供无状态的应用的性能。如果 `Authentication` 拥有一个缓存中对象的引用（例如 `UserDetails` 对象的引用），而这个对象的凭据被移除了，那么它以后就不能依据缓存的值进行授权了。如果你使用缓存的话，你需要考虑把这一点。一个显而易见的方案，就是拷贝一份这个对象，在缓存实现中或者在新建返回的 `Authentication` 的 `AuthenticationProvider` 中。另外，你也可以关闭 `ProviderManager` 中的 `eraseCredentialsAfterAuthentication` 属性。查看 JavaDoc 来获得更多的信息。



**DaoAuthenticationProvider**

Spring Security 实现的最简单的 `AuthenticationProvider` 是 `DaoAuthenticationProvider` 。这也是框架最早支持的实现。它利用 `UserDetailsService` （作为一个 DAO）来寻找用户名，密码和 `GrantedAuthority` 。它的认证方式就是简单地对比提交在 `UsernamePasswordAuthenticationToken` 中的密码和加载在 `UserDetailsService` 中的。配置这个提供者是十分简答的：

```xml
<bean id="daoAuthenticationProvider"
    class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
<property name="userDetailsService" ref="inMemoryDaoImpl"/>
<property name="passwordEncoder" ref="passwordEncoder"/>
</bean>
```

`PasswordEncoder` 是可选的。一个 `PasswordEncoder` 提供了编码和反编码从配置的 `UserDetailsService` 返回的 `UserDetails` 中的密码的功能。在下面你可以看到更多的讨论。



##### 8.2.2 UserDetailsService 实现

在这份参考手册之前提到的，大多数的认证实现都利用了 `UserDetails` 和 `UserDetailsService` 接口。回忆一下 `UserDetailsService` 接口只定义了一个方法：

```java
UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
```

返回的 `UserDetails` 是一个接口，它提供了返回非空返回值的 getter 方法，例如用户名， 密码，授权的认证，用户账户是否被使能。大多是认证提供者都会使用 `UserDetails` 对象，即使用户名和密码在他们的这一部分认证决定中不需要被使用。他们可能使用返回 `UserDetails` 对象，只是为了它的 `GrantedAutheority` 信息。因为一些其他的系统（例如，LDAP 或者 x.509 或 CAS 等等）实际上承担了验证授权资格的工作。

鉴于 `UserDetailsService` 的实现是十分简单的，所以对于使用者来说，用他们选择的持久化策略从中获取认证信息是很容易的。当然，Spring Security 也提供了一些有用的基础实现，我们下面来看一下。



**In-Memory 认证**

用自定义的 `UserDetailsService` 实现从选择的持久化引擎中提取出信息。但是，大多数应用不需要这样的复杂度。如果你构建的是一个单独的应用，或者只是开始集成 Spring Security，这确实不必要。因为这个时候，你并不想把时间花在配置数据库或者写一个 `UserDetailsService` 实现上。对于这种情况，一个简单的选择是在安全命名空间中使用 `user-service` 对象：

```xml
<user-service id="userDetailsService">
<!-- Password is prefixed with {noop} to indicate to DelegatingPasswordEncoder that
NoOpPasswordEncoder should be used. This is not safe for production, but makes reading
in samples easier. Normally passwords should be hashed using BCrypt -->
<user name="jimi" password="{noop}jimispassword" authorities="ROLE_USER, ROLE_ADMIN" />
<user name="bob" password="{noop}bobspassword" authorities="ROLE_USER" />
</user-service>
```

也支持外部配置文件，例如

```xml
<user-service id="userDetailsService" properties="users.properties"/>
```

外部配置文件应该包含这样格式的内容：

```properties
username=password,grantedAuthority[,grantedAuthority][,enabled|disabled]
```

举例来说：

```properties
jimi=jimispassword,ROLE_USER,ROLE_ADMIN,enabled
bob=bobspassword,ROLE_USER,enabled
```



**JdbcDaoImpl**

Spring Security 也有一个 `UserDetailsService` 来从 JDBC 数据源获取权限。在内部，Spring JDBC 被使用了，所以它避免了全功能的对象关系映射（ORM）带来的复杂性，只是存储用户信息。如果你的应用使用了一个 ORM 工具，你可能希望写一个定制化的 `UserDetailsService` 来重用这些你大概早已创建好的映射文件。返回到 `JdbcDaoImpl`，一个配置好的示例如下：

```xml
<bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
<property name="driverClassName" value="org.hsqldb.jdbcDriver"/>
<property name="url" value="jdbc:hsqldb:hsql://localhost:9001"/>
<property name="username" value="sa"/>
<property name="password" value=""/>
</bean>

<bean id="userDetailsService"
    class="org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl">
<property name="dataSource" ref="dataSource"/>
</bean>
```

你可以通过修改 `DriverManagerDataSource` 来使用不同的数据库管理系统。你也可以使用一个从 JNDI 获取的的全局的数据源，和 Spring 的其他任何配置一样。



**Authority Group**

默认地，`JdbcDaoImpl` 假设权限是直接关联到用户身上的（查看 数据库 [schema appendix](章节 14.1 安全数据库 Schema)），所以它只为单独的用户加载权限信息。另一种方式是把用户分类到不用的组，并且把组关联到用户上。一些人喜欢这种方式，因为这是一种管理用户的方式。查看 `JdbcDaoImpl` 的 JavaDoc 来获取更多的信息，例如怎样使能用户分组权限等。分组 schema 包括在附录中。



##### 8.2.2 密码编码

Spring Security 的 `PasswordEncoder` 接口用来对密码的单向转换，保证密码的安全存储。因为 `PasswordEncoder` 是单向转换，当密码需要双向转换时候，它并不够用（举例，存储用于对数据库进行身份验证的凭据）。典型的 `PasswordEncoder` 用来存储密码，每一次认证时候都需要和用户提供的密码进行比对。



**密码的历史**

这么多年来，存储密码的标准机制一直在进化。一开始的时候，密码是存储在纯文件中。密码被认定是安全的，因为我们存储的数据是需要凭证来获取的。然后，恶意用户可以找到方式来获取大量的用户名和密码 “data dump”  ，例如使用 SQL 注入的方式。随着越来越多的用户数据被公布，专家意识到我们需要做更多的工作来保护用户的密码。

开发者被鼓励在使用单向 hash ，例如，SHA-256，密码之后再存储。当一个用户试着去认证，哈希过的密码被用来和用户传入的密码经过哈希之后值进行比较。这意味着系统只需要存储单向哈希后的密码。如果异常发生，那么只有单向的密码哈希被暴露。由于哈希是单向的加密方式，因此在计算上从给定的哈希值猜测密码十分困难，在系统上找出每一个密码是不值得的。为了打败这个新系统，恶意用户决定创建一个新的查找表，就是所谓的"Rainbow Table" 。与其在每一次都干猜测密码的活，不如全部计算一次存储起来。

为了减轻 Rainbow Table 的有效性，开发者被鼓励使用加盐的密码。不只是把密码进行哈希加密，随机的 byte（就是所谓的盐）也用来保护用户的密码。盐和用户的密码会用来进行哈希计算，产生一个独一无二的哈希。盐会以明文的形式存储在用户的密码旁。然后当一个用户试着去认证，这个独一无二的哈希值会和存储的盐与用户打印的密码经过哈希后的值进行比较。这个独一无二的盐意味着 Rainbow Table 不再有效了，因为对于每一个盐和用户密码的组合都是不同的。

在当代，我们意识到加密哈希（例如，SHA-256）不再安全。理由是现在的软件，我们可以在一秒钟进行数亿次哈希计算。这意味着我们可以轻松地单独破解所有密码。

开发者现在被鼓励利用自适应的单向函数来存储密码。自适应单向函数验证密码是资源敏感的（例如，CPU 资源，内存资源，等等）。一个自适应的单向函数允许配置一个 “work factor” （work 因子），这会随着硬件变得更快而增长。建议值是设置系统需要使用大约 1 秒钟来验证密码。这里的平衡点是，让攻击者破解密码十分困难，而又不会造成系统过大的负担。Spring Security 尝试着为 “work factor” 提供一个良好的起点。但是用户被鼓励去自定义这个一年春，因为系统与系统之间的差别是非常大的。自适应函数的例子，包括，bcrypt，PBKDF2，scrypt 和 Argon 2。

因为自适应单向函数，是资源敏感型的，在每一次请求时验证用户名和密码会显著降低应用的性能。





##### 8.2.3 密码编码

Spring Security 的 `PasswordEncoder` 接口用来对密码的单向转换，保证密码的安全存储。因为 `PasswordEncoder` 是单向转换，当密码需要双向转换时候，它并不够用（举例，存储用于对数据库进行身份验证的凭据）。典型的 `PasswordEncoder` 用来存储密码，每一次认证时候都需要和用户提供的密码进行比对。



**密码的历史**

这么多年来，存储密码的标准机制一直在进化。一开始的时候，密码是存储在纯文件中。密码被认定是安全的，因为我们存储的数据是需要凭证来获取的。然后，恶意用户可以找到方式来获取大量的用户名和密码 “data dump”  ，例如使用 SQL 注入的方式。随着越来越多的用户数据被公布，专家意识到我们需要做更多的工作来保护用户的密码。

开发者被鼓励在使用单向 hash ，例如，SHA-256，密码之后再存储。当一个用户试着去认证，哈希过的密码被用来和用户传入的密码经过哈希之后值进行比较。这意味着系统只需要存储单向哈希后的密码。如果异常发生，那么只有单向的密码哈希被暴露。由于哈希是单向的加密方式，因此在计算上从给定的哈希值猜测密码十分困难，在系统上找出每一个密码是不值得的。为了打败这个新系统，恶意用户决定创建一个新的查找表，就是所谓的"Rainbow Table" 。与其在每一次都干猜测密码的活，不如全部计算一次存储起来。

为了减轻 Rainbow Table 的有效性，开发者被鼓励使用加盐的密码。不只是把密码进行哈希加密，随机的 byte（就是所谓的盐）也用来保护用户的密码。盐和用户的密码会用来进行哈希计算，产生一个独一无二的哈希。盐会以明文的形式存储在用户的密码旁。然后当一个用户试着去认证，这个独一无二的哈希值会和存储的盐与用户打印的密码经过哈希后的值进行比较。这个独一无二的盐意味着 Rainbow Table 不再有效了，因为对于每一个盐和用户密码的组合都是不同的。

在当代，我们意识到加密哈希（例如，SHA-256）不再安全。理由是现在的软件，我们可以在一秒钟进行数亿次哈希计算。这意味着我们可以轻松地单独破解所有密码。

开发者现在被鼓励利用自适应的单向函数来存储密码。自适应单向函数验证密码是资源敏感的（例如，CPU 资源，内存资源，等等）。一个自适应的单向函数允许配置一个 “work factor” （work 因子），这会随着硬件变得更快而增长。建议值是设置系统需要使用大约 1 秒钟来验证密码。这里的平衡点是，让攻击者破解密码十分困难，而又不会造成系统过大的负担。Spring Security 尝试着为 “work factor” 提供一个良好的起点。但是用户被鼓励去自定义这个一年春，因为系统与系统之间的差别是非常大的。自适应函数的例子，包括，bcrypt，PBKDF2，scrypt 和 Argon 2。

因为自适应单向函数，是资源敏感型的，在每一次请求时验证用户名和密码都会显著降低应用的性能。无论是 Spring Security 或是其他的第三方库来提升验证密码的性能，因为它的安全性本身就是通过使验证成为资源敏感性操作来保证的。用户被鼓励使用短期的验证凭据来替换长期的验证凭据，例如，用 session，OAuth Token 等等来替换用户名和密码。短期的凭据可以更快的验证，并且不丢失任何的安全性。



**DelegatingPasswordEncoder**

Spring Security 5.0 之前的默认 `PasswordEncoder` 是 `NoOpPasswordEncoder` ，这要求纯文字密码。基于上一章的 `密码的历史`，你可能已经猜到了现在的默认 `PasswordEncoder` 是类似于 `BCryptPasswordEncoder` 之类的东西。然后，这忽略了三个重要的现实问题：

* 有许多老旧的应用仍旧使用就的密码编码方式，而且不能简单的迁移
* 在未来，最好的密码存储方式会再一次改变
* Spring Security 作为一个框架，不能频繁地做出突破变化

因此，Spring Security 引入了 `DeletatingPasswordEncoder`，这通过以下方式解决了上述的问题：

* 确保使用当前的推荐的密码保存方式时，密码会被加密
* 允许以现在或旧地方式验证密码
* 允许在将来升级密码加密方式

你可以很容易地使用 `PasswordEncoderFactories` 来构造一个 `DelegatingPasswordEncoder` 实例。

```java
PasswordEncoder passwordEncoder =
    PasswordEncoderFactories.createDelegatingPasswordEncoder();
```

另外，你也可以自定义自己的示例。例如：

```java
String idForEncode = "bcrypt";
Map encoders = new HashMap<>();
encoders.put(idForEncode, new BCryptPasswordEncoder());
encoders.put("noop", NoOpPasswordEncoder.getInstance());
encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
encoders.put("scrypt", new SCryptPasswordEncoder());
encoders.put("sha256", new StandardPasswordEncoder());

PasswordEncoder passwordEncoder =
    new DelegatingPasswordEncoder(idForEncode, encoders);
```



**密码保存格式**

常用的保存格式是：

```
{id}encodedPassword
```

`id` 位置是标记位，用来寻找哪一个 `PasswordEncoder` 应该被使用，`encoderedPassword` 是被选择的 `PasswordEncoder` 编译的原始密码。`id` 一定在要在密码的开始位，以 `{` 开始， `}` 结束。如果 `id` 没有被找到，那么 `id` 就被认为是 null 。举例来说，下面的可是一列表的使用不同的 `id` 编译过的密码。所有的原始密码都是 “password” ：

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG 
{noop}password 
{pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc 
{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=  
{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0 
```

* 第一个编译过的密码 `id`，是 `bcrypt` ，对应的编译器是 `BCryptPasswordEncoder` 。
* 第二个编译过的密码 `id`，是 `noop` ，对应的编译器是 `NoOpPasswordEncoder` 。
* 第三个编译过的密码 `id`，是 `pbkdf2`，对应的编译器是 `Pbkdf2PasswordEncoder` 。
* 第四个编译过的密码 `id`，是 `scrypt`，对应的编译器是 `ScryptPasswordEncoder` 。
* 第五个编译过的密码 `id`， 是 `sha256`，对应的编译器是 `StandardPasswordEncoder` 。

> 有些使用者可能会担心存储的方式被潜在攻击者了解。这不需要关系，因为密码的存储不依赖加密算法作为一个秘密。此外，大多数格式在没有前缀的情况下，也很容易被进攻者知晓。举例来说，`BCrypt` 密码通常以 `$2a$` 开头。
>



**密码编码**

`idForEncode` 被传给 `PasswordEncoder` 的构造器，用来选择 `PasswordEncoder` 。在我们上面构造的`DelegatingPasswordEncoder` 中，这意味着 `password` 的编码结果会被委托给 `BCryptPasswordEncoder` ，生成的结果以 `{bcrypt}` 开头。最终结果大概是这样： 

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```



**密码匹配**

匹配是基于 `id` 和 `id` 对应的 `PasswordEncoder` 来进行的。我们例子在 `密码存储格式（Password Storage Format）`  章节中展示。默认地，用一个密码和一个找不到匹配对象的 `id` 来调用 `matches(CharSequence, String)`  的结果会造成一个 `IllegalArgumentException` 。这个行为可以使用 `DelegatingPasswordEncoder.setDefaultPasswordEncoder(PasswordEncoder)` 来进行定制化。

通过使用 `id`，我们可以匹配任何的密码编码方式，但是使用最现代的编码方式对密码进行编码。这是很重要的，因为和加密不同，密码的哈希计算方式被设计为没有简单地方式反向恢复。因为没有简单方式来恢复，所以迁移密码是很困难的。然而，`NoOpPasswordEncoder` 对使用者来说是很简单的，我们选择默认包含这个类，来使得初使用者有良好体验。



**初体验**

如果你在写一个 demo 或者 示例，花时间为你的用户哈希密码是个很笨重的事情。有一个便利的机制来使它很简单，但是在实际生产仍不推荐使用。

```java
User user = User.withDefaultPasswordEncoder()
  .username("user")
  .password("password")
  .roles("user")
  .build();
System.out.println(user.getPassword());
// {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

如果你有很多用户，你可以继续使用这些 builder ：

```java
UserBuilder users = User.withDefaultPasswordEncoder();
User user = users
  .username("user")
  .password("password")
  .roles("USER")
  .build();
User admin = users
  .username("admin")
  .password("password")
  .roles("USER","ADMIN")
  .build();
```

它对存储的密码进行哈希，但是密码仍旧暴露在内存中和编译的源码中。因此，在生产环境中仍旧不被认为是安全的。对于生产环境，你应该在外部哈希你的密码。



**故障排除**

在密码存储格式示例中，接下来的异常会产生，只有当其中一个密码的 `id` 找不到匹配值时：

```java
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder$UnmappedIdPasswordEncoder.matches(DelegatingPasswordEncoder.java:233)
    at org.springframework.security.crypto.password.DelegatingPasswordEncoder.matches(DelegatingPasswordEncoder.java:196)
```

最简单的方式去解决这个问题的方式，是明确地选择一个 `ProviderEncoder` 来编码你的密码。最简单的方式是搞清楚你的密码当前被存储的正确格式，并明确地选择 `ProviderEncoder` 。如果你正在从 Spring Security 4.2.x ，你可以通过暴露一个 `NoOpPasswordEncoder` 来回到原来的行为。举例来说，如果你是用 Java Configuration，你可以创建一个配置类，类似于：

> 回到 `NoOpPasswordEncoder` 并不被认为是安全的。你应该迁移到使用 `DelegatingPasswordEncoder` 来支持安全的密码编码。

```java
@Bean
public static NoOpPasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();
}
```

如果你是用 XML 配置，你可以暴露一个 `PasswordEncoder` 和一个 id `passwordEncoder` 。

```XML
<b:bean id="passwordEncoder"
        class="org.springframework.security.crypto.password.NoOpPasswordEncoder" factory-method="getInstance"/>
```

额外地，你可以在你的密码前面加一个正确的 id 然后继续使用 `DelegatingPasswordEncoder` 。举例来说，如果你是用 BCrypt，你可以迁移你的密码类似于：

```
$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

到

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
```

一个完整的映射的列表可以看 PasswordEncoderFactories 的 Java Doc。



**BCryptPasswordEncoder**

`BCryptPasswordEncoder` 实现广泛地支持 bcrpt 算法来哈希密码。为了密码的破解难度更稳定，bcrypt 特意计算地十分慢。像其他的自适应的单向函数，它应该被设置为在你的系统上需要 1 秒来检验密码。

```java
// Create an encoder with strength 16
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(16);
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```



**Pbkdf2PasswordEncoder**

`Pbkdf2PasswordEncoder` 实现使用 PBKDF2 算法来哈希密码。为了击败密码破译程序，它也是故意设计的很慢。像其他的自适应单向函数，它应该被设置为在你的系统上需要 1 秒来检验密码。如果需要 FIPS 证书，那么算法是一个不错的选择。

```java
// Create an encoder with all the defaults
Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```



**ScryptPasswordEncoder**

`ScryptPasswordEncoder` 实现使用 scrypt 算法来哈希密码。为了击败密码破译程序，它也是故意设计的很慢。像其他的自适应单向函数，它应该被设置为在你的系统上需要 1 秒来检验密码。

```java
// Create an encoder with all the defaults
SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
String result = encoder.encode("myPassword");
assertTrue(encoder.matches("myPassword", result));
```



**其他的 PasswordEncoder**

`PasswordEncoder` 有大量的实现，完全支持向后兼容。它们全部被弃用了，说明它们不在认为是安全的。然而，因为已有的老系统迁移是十分困难的，所以并没有计划要把这些移除。



##### 8.2.4 Jackson 支持

Spring Security 增加了 Jackson 支持来持久化 Spring Security 相关的类。在一个分布式会话中，这可以提升系列化 Spring Security 相关类的性能（会话复制，Spring Session 等等）。

为了使用它，要注册 `SecurityJackson2Modules.getModules(ClassLoader)` 作为 Jackson Modules。

```java
ObjectMapper mapper = new ObjectMapper();
ClassLoader loader = getClass().getClassLoader();
List<Module> modules = SecurityJackson2Modules.getModules(loader);
mapper.registerModules(modules);

// ... use ObjectMapper as normally ...
SecurityContext context = new SecurityContextImpl();
// ...
String json = mapper.writeValueAsString(context);
```
















