package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import java.security.Principal;
import javax.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private OrderRepository orders;
    private AccessService access;

    @GetMapping("/{id}")
    public Order show(@PathVariable Long id) {
        // expect: spring-idor-unscoped-lookup
        return orders.findById(id).orElseThrow();
    }

    @DeleteMapping("/{orderId}")
    public void destroy(@PathVariable("orderId") Long orderId) {
        // expect: spring-idor-unscoped-lookup
        orders.deleteById(orderId);
    }

    @GetMapping("/{id}/scoped")
    public Order scoped(@PathVariable Long id, @AuthenticationPrincipal AppUser user) {
        return orders.findByIdAndOwnerId(id, user.getId()).orElseThrow();
    }

    @GetMapping("/{id}/guarded")
    @PreAuthorize("@access.canRead(#id, authentication)")
    public Order guarded(@PathVariable Long id) {
        return orders.findById(id).orElseThrow();
    }

    @GetMapping("/{id}/checked")
    public Order checked(@PathVariable Long id, Principal principal) {
        Order o = orders.findById(id).orElseThrow();
        if (!o.getOwner().equals(principal.getName())) {
            throw new ForbiddenException();
        }
        return o;
    }

    @GetMapping("/{id}/helper")
    public Order helper(@PathVariable Long id) {
        access.checkOwnership(id);
        return orders.findById(id).orElseThrow();
    }

    @GetMapping("/catalog/{id}")
    public Order publicCatalog(@PathVariable Long id) {
        return orders.findById(id).orElseThrow(); // securecode: public-object
    }

    @PostMapping
    // expect: spring-requestbody-without-valid
    public Order create(@RequestBody Order order) {
        // expect: spring-mass-assignment-entity-binding
        return orders.save(order);
    }

    @PostMapping("/v2")
    public Order createFromDto(@Valid @RequestBody CreateOrderRequest req, @AuthenticationPrincipal AppUser user) {
        Order o = new Order();
        o.setItem(req.getItem());
        o.setOwnerId(user.getId());
        return orders.save(o);
    }

    @PostMapping("/webhook")
    public void webhook(@RequestBody String raw) {
        access.verifySignature(raw);
    }
}
