package com.spring.vaidya.service;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.vaidya.entity.PasswordResetToken;
import com.spring.vaidya.entity.User;
import com.spring.vaidya.repo.PasswordResetTokenRepository;
import com.spring.vaidya.repo.UserRepository;

@Service
public class UserService {
	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordResetTokenRepository tokenRepository;

	@Autowired
	private EmailService emailService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
	}

	public User registerUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepository.save(user);
	}

	public void initiateForgotPassword(String email) {
		User user = userRepository.findByUserEmailIgnoreCase(email)
				.orElseThrow(() -> new RuntimeException("User not found"));

		String token = UUID.randomUUID().toString();
		PasswordResetToken resetToken = new PasswordResetToken();
		resetToken.setToken(token);
		resetToken.setUser(user);
		resetToken.setExpiryDate(LocalDateTime.now().plusMinutes(30));
		tokenRepository.save(resetToken);

		emailService.sendPasswordResetEmail(email, token);
	}

	public void resetPassword(String token, String newPassword) {
		PasswordResetToken resetToken = tokenRepository.findByToken(token)
				.orElseThrow(() -> new RuntimeException("Invalid or expired token"));

		if (resetToken.isExpired()) {
			throw new RuntimeException("Token has expired");
		}

		User user = resetToken.getUser();
		user.setPassword(passwordEncoder.encode(newPassword));
		userRepository.save(user);

		tokenRepository.delete(resetToken);

		/*
		 * public Optional<User> findByUsername(String username) { return
		 * userRepository.findByUsername(username); }
		 */
	}
}
