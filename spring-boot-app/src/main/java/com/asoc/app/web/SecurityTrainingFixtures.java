package com.asoc.app.web;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("demo-vuln")
public class SecurityTrainingFixtures {

    public String unsafeQueryExample(String username) {
        String password = "demo-hardcoded-secret";
        return "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    }
}

