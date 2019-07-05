package com.gozman.security.controllers;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SampleController {

    /*
    * see allowed role in Security.java
     */
    @RequestMapping("/t1")
    public String testRoleGozman(){
        return "test 11";
    }

    @RequestMapping("/t2")
    public Principal getLoggedUser(Principal principal){
        return principal;
    }

    @PreAuthorize("hasRole('USER')")
    @RequestMapping("/t3")
    public String testRoleUser(){
        return "test user";
    }

    @RequestMapping("/public")
    public String getPublic(){
        return "public";
    }
}
