package Spring.Security.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class WebController {
    @GetMapping("/")
    public String home() {
        return "welcome";

    }

    @GetMapping("/welcome")
    public String welcomePage() {
        return "welcome";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/admin")
    public String adminPage() {
        return "admin";
    }

    @GetMapping("/user")
    public String userPage() {
        return "user";

    }
}
