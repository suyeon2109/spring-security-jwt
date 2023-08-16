package com.gbsoft.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.gbsoft.domain.User;
import com.gbsoft.dto.UserDto;
import com.gbsoft.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class UserController {
	private final UserService userService;

	@PostMapping("/signup")
	public ResponseEntity<User> signup(@Valid @RequestBody UserDto userDto) {
		return ResponseEntity.ok(userService.signup(userDto));
	}

	@GetMapping("/user")
	@PreAuthorize("hasAnyRole('USER','ADMIN')")
	public ResponseEntity<User> getMyUserInfo() {
		return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
	}

	@GetMapping("/user/{username}")
	@PreAuthorize("hasAnyRole('ADMIN')")
	public ResponseEntity<User> getUserInfo(@PathVariable String username) {
		return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
	}
}