package demo;

// Test fixture for semgrep/java-spring.yml: cases found by the independent review. Never compiled or run.

import java.security.MessageDigest;
import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class ReviewCases {

    private OrderRepository orders;
    private RestTemplate rest;

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
            // expect: spring-permitall-sensitive-path
            .requestMatchers("/env").permitAll()
            // expect: spring-permitall-sensitive-path
            .requestMatchers("/console").permitAll()
            .requestMatchers("/environment-info").permitAll()
            .anyRequest().authenticated());
        return http.build();
    }

    public DocumentBuilder secureProcessingOnly() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // expect: java-xxe-documentbuilderfactory
        return dbf.newDocumentBuilder();
    }

    @GetMapping("/orders/{id}/nullcheck")
    public Order nullCheckOnly(@PathVariable Long id, Principal principal) {
        if (principal == null) {
            throw new ForbiddenException();
        }
        // expect: spring-idor-unscoped-lookup
        return orders.findById(id).orElseThrow();
    }

    @PostMapping("/qualified")
    public void qualifiedValid(@RequestBody @jakarta.validation.Valid CreateOrderRequest req) {
        orders.touch(req.getItem());
    }

    @GetMapping("/proxy")
    public Object proxy(@RequestParam String p, String baseUrl) {
        return rest.execute(baseUrl + "/items/" + p, org.springframework.http.HttpMethod.GET, null, null);
    }

    String hashPasswordResetToken(String token) throws Exception {
        return new String(MessageDigest.getInstance("SHA-256").digest(token.getBytes()));
    }

    void shuffleMappings(List<String> m) {
        Collections.shuffle(m, new Random());
    }
}
