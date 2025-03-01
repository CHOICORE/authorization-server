package me.choicore.samples.authorization.ui

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class LoginController {
    @GetMapping("/sign-in")
    fun signIn(model: Model): String = "account/login-form"
}
