package com.example.SocialJwtApplication.SecurityJWTUtils;

import com.example.SocialJwtApplication.Model.User;
import com.example.SocialJwtApplication.Repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl {

    @Autowired
    private UserRepository userRepository;

    public User loadUserByUsernameOrEmail(String usernameOrEmail){
        Optional<User> userOpt = userRepository.findByUsername(usernameOrEmail);
        if (userOpt.isEmpty()){
            userOpt = userRepository.findByEmail(usernameOrEmail);
        }
        return userOpt.orElse(null);
    }
    public User loadUserById(Long id){
        return userRepository.findById(id).orElse(null);
    }
}
