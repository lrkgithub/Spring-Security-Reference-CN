#### 13 Spring Data 集成

Spring Security 提供了 Spring Data 集成，这允许引用查询中的当前对象。在请求中包括用户以支持分页，不仅仅是好用的，而且是必须的，因为在后面过滤将导致无法扩展。



##### 13.1 Spring Data & Spring Security 配置

为了使用这项支持，需要增加 `org.springframework.securtiy:spring-security-data` 依赖，并提供一个 `SecurityEvaluationContextExtension` 类型的 bean 。在 Java 配置中，这看上去像是：

```Java
@Bean
public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
    return new SecurityEvaluationContextExtension();
}
```

在 XML 配置，这会像是：

```XML
<bean class="org.springframework.security.data.repository.query.SecurityEvaluationContextExtension"/>
```



##### 13.2 使用 @Query 的 Security 表达式

现在 Spring Security 可以在你的查询中使用。比如说：

```Java
@Repository
public interface MessageRepository extends PagingAndSortingRepository<Message,Long> {
    @Query("select m from Message m where m.to.id = ?#{ principal?.id }")
    Page<Message> findInbox(Pageable pageable);
}
```

这项检查会判断是否 `Authentication.getPrincipal().getId()` 与 `Message` 的 recipient 相等。注意到，这个示例假设你自己已经自定义了 principal 是一个拥有 Id 的对象。通过暴露 `SecurityEvaluationContextExtension` bean，所有的 [常用安全表达式](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/#common-expressions)  都能在 Query 中使用。