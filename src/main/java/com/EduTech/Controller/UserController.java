package com.EduTech.Controller;

import com.EduTech.Model.User;
import com.EduTech.Service.EmailService;
import com.EduTech.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api/users")
public class UserController
{

    @Autowired
    private UserRepo repo;

    @Autowired
    private EmailService emailService;


    @GetMapping("/getAll")
    public List <User> getAllUsers()
    {
        return repo.findAll();
    }


    @PostMapping("/register")
    public String registerUser(@RequestBody User user)
    {
        if (repo.findByUserName(user.getUserName()) != null) {
            return "Username is already taken";
        }

        if (repo.findByEmail(user.getEmail()) != null) {
            return "Email is already in use";
        }

        if (!isValidEmail(user.getEmail())) {
            return "Invalid email format";
        }

        if (!isValidPassword(user.getPassword())) {
            return "Password does not meet the requirements";
        }

        if (!isValidPhoneNumber(user.getPhoneNumber())) {
            return "Phone number must be exactly 10 digits";
        }

        user.setScore(0);
        user.setRegistrationTime(LocalDateTime.now());

        repo.save(user);

        String subject = "Registration Successful";
        String body = "Dear " + user.getFirstName() + " " + user.getLastName() + ",\n\n" +
                "Your registration was successful.\n\n" +
                "Best regards,\nEduTech Team";

        emailService.sendEmail(user.getEmail(), subject, body);

        return "User registered successfully";

    }

    @PostMapping("/login/{email}/{password}")
    public String login(@PathVariable String email, @PathVariable String password) {
        User P1 = repo.findByEmail(email);
        if (P1 != null && P1.getPassword().equals(password)) {
            return "Login Successful";
        } else {
            return "Login Failed";
        }
    }

    @PutMapping("/updateScore/{id}/{score}")
    public String updateScore(@PathVariable Long id, @PathVariable int score) {
        Optional<User> P1 = repo.findById(id);
        if (P1.isPresent()) {
            User user = P1.get();
            user.setScore(score);
            repo.save(user);
            return "Score updated successfully for user ID: " + id;
        } else {
            return "User not found with ID: " + id;
        }
    }

    @PutMapping("/updatePassword/{id}/{password}")
    public String updatePassword(@PathVariable Long id, @PathVariable String password)
    {
        Optional<User> P1 = repo.findById(id);
        if (P1.isPresent())
        {
            User user = P1.get();
            user.setPassword(password);
            repo.save(user);
            return "Password updated successfully";
        }
        else
        {
            return "User not found with id";
        }

    }

    @DeleteMapping("/delete/{email}")
    public String deleteUserByEmail(@PathVariable String email)
    {
        User P1 = repo.findByEmail(email);
        if(P1==null)
        {
            return "User not found with the mail";
        }
        else
        {
            repo.deleteById(P1.getId());
        }
        return "User associated with " + email + " is now deleted";
    }




    private boolean isValidPassword(String password) {
        if (password.length() < 8) {
            return false;
        }
        if (!password.matches(".*[A-Z].*")) {
            return false;
        }
        if (!password.matches(".*[a-z].*")) {
            return false;
        }
        if (!password.matches(".*\\d.*")) {
            return false;
        }
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) {
            return false;
        }
        return true;
    }
    private boolean isValidEmail(String email)
    {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
        Pattern pat = Pattern.compile(emailRegex);
        return email != null && pat.matcher(email).matches();
    }
    private boolean isValidPhoneNumber(String phoneNumber) {
        return phoneNumber != null && phoneNumber.matches("\\d{10}");
    }

}
