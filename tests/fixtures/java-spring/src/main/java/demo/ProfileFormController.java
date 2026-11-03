package demo;

// Test fixture for semgrep/java-spring.yml. Never compiled or run.

import javax.validation.Valid;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

@Controller
public class ProfileFormController {

    private UserRepository users;

    @PostMapping("/profile")
    public String update(@ModelAttribute User user) {
        // expect: spring-mass-assignment-entity-binding
        users.save(user);
        return "redirect:/profile";
    }

    @PostMapping("/profile/form")
    public String updateFromForm(@Valid @ModelAttribute ProfileForm form) {
        users.updateName(form.getName());
        return "redirect:/profile";
    }
}

@Controller
class SafeBinderController {

    private UserRepository users;

    @InitBinder
    void binder(WebDataBinder binder) {
        binder.setAllowedFields("name", "email");
    }

    @PostMapping("/settings")
    public String update(@ModelAttribute User user) {
        users.save(user);
        return "redirect:/settings";
    }
}
