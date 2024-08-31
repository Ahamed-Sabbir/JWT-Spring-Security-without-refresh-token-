package com.sabbir.controller;

import com.sabbir.model.User;
import com.sabbir.service.UserService;
import com.sabbir.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RestApiController {
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    public RestApiController(JwtUtil jwtUtil, UserService userService, AuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/user/registration")
    public String UserRegesitration(@RequestBody User user){
        if(userService.findUserByUsername(user.getUsername()) != null){
            return "user exits";
        }
        userService.saveUser(user);
        return "user registration successful";
    }

    @PostMapping("/admin/registration")
    public String AdminRegesitration(@RequestBody User user){
        if(userService.findUserByUsername(user.getUsername()) != null){
            return "admin exits";
        }
        userService.saveAdmin(user);
        return "admin registration successful";
    }

    @PostMapping("/login")
    public String login(@RequestBody User user) {
        try {
            // check if username + password is correct
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            //create jwt token
            return jwtUtil.generateToken(userDetails);
        }
        catch (Exception ex){
            return "Invalid Credentials";
        }
    }
}
