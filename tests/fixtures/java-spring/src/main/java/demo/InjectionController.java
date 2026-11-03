package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;
import javax.naming.InitialContext;
import javax.persistence.EntityManager;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class InjectionController {

    private EntityManager em;
    private JdbcTemplate jdbc;
    private Connection conn;
    private static final String TABLE = "orders";

    @GetMapping("/jndi")
    public Object jndi(@RequestParam String name) throws Exception {
        InitialContext ctx = new InitialContext();
        // expect: java-jndi-injection
        return ctx.lookup(name);
    }

    @GetMapping("/jndi-fixed")
    public Object jndiFixed(@RequestParam String name) throws Exception {
        InitialContext ctx = new InitialContext();
        return ctx.lookup("java:comp/env/jdbc/main");
    }

    @GetMapping("/calc")
    public Object calc(@RequestParam("expr") String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        // expect: java-spel-injection
        return parser.parseExpression(expr).getValue();
    }

    @GetMapping("/calc-fixed")
    public Object calcFixed(@RequestParam("expr") String expr) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression("#root.total * 2").getValue();
    }

    @GetMapping("/users")
    public List<?> jpql(@RequestParam String name) {
        // expect: java-sqli-string-concat
        return em.createQuery("select u from User u where u.name = '" + name + "'").getResultList();
    }

    @GetMapping("/users-native")
    public List<?> nativeSql(@RequestParam String sort) {
        String sql = "select * from users order by " + sort;
        // expect: java-sqli-string-concat
        return em.createNativeQuery(sql).getResultList();
    }

    @GetMapping("/users-jdbc")
    public Object jdbcConcat(@RequestParam String id) throws Exception {
        Statement st = conn.createStatement();
        // expect: java-sqli-string-concat
        return st.executeQuery("select * from users where id = " + id);
    }

    @GetMapping("/users-template")
    public Object templateFormat(@RequestParam String email) {
        // expect: java-sqli-string-concat
        return jdbc.queryForList(String.format("select * from users where email = '%s'", email));
    }

    @GetMapping("/users-safe")
    public List<?> jpqlSafe(@RequestParam String name) {
        return em.createQuery("select u from User u where u.name = :name").setParameter("name", name).getResultList();
    }

    @GetMapping("/users-safe-jdbc")
    public Object jdbcSafe(@RequestParam String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("select * from users where id = ?");
        ps.setString(1, id);
        return ps.executeQuery();
    }

    @GetMapping("/users-safe-template")
    public Object templateSafe(@RequestParam String email) {
        return jdbc.queryForList("select * from users where email = ?", email);
    }

    @GetMapping("/constant")
    public Object constantConcat() {
        return jdbc.queryForList("select count(*) from " + "orders");
    }
}
