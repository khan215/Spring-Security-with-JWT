package com.jwtspringsecurity.jwtspringsecurity.Controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @RequestMapping({"/hello"})
    public String getHello(){
        return "Hello World !";
    }


}
