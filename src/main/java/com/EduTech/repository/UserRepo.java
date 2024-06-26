package com.EduTech.repository;

import com.EduTech.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository <User, Long>{


    User findByUserName(String username);

    User findByEmail(String email);
}
