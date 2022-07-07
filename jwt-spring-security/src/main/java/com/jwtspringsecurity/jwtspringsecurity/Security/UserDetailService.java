package com.jwtspringsecurity.jwtspringsecurity.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User("dawood",
                "$2a$10$6KZMKMNhrEW3s3SslEB2C.rhNTiuYuGRriZuABKJFRVme6kRG1TqS",
                new ArrayList<>());
    }
}
