package com.crm.demo;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // Spring automatically "injects" the repository and password encoder here
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // 1. Add new user
    public User registerUser(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already in use");
        }

        User newUser = new User();
        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setRole(request.getRole());

        newUser.setPasswordHash(passwordEncoder.encode(request.getPassword()));

        if (request.getRole() == Role.ADMIN) {
            newUser.setRole(Role.STUDENT);
        } else {
            newUser.setRole(request.getRole() != null ? request.getRole() : Role.STUDENT);
        }

        return userRepository.save(newUser);
    }

    // 2. Get user by id
    public Optional<User> getUserById(UUID id) {
        return userRepository.findById(id);
    }

    // 3. List of users by role
    public List<User> getUsersByRole(Role role) {
        return userRepository.findByRole(role);
    }

    // 4. Delete user
    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }
    // 5. User Login
    public String login(String email, String rawPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        return jwtUtil.generateToken(user.getEmail(), user.getRole().name());
    }
    // Get all users in the database
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    //update profile
    public void updateProfile(java.util.UUID id, com.crm.demo.UpdateRequest request) {
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        if (request.getName() != null) {
            existingUser.setName(request.getName());
        }
        userRepository.save(existingUser);
    }
}