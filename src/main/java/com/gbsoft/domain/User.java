package com.gbsoft.domain;

import static jakarta.persistence.GenerationType.*;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {

	@JsonIgnore
	@Id
	@Column(name = "user_id")
	@GeneratedValue(strategy = IDENTITY)
	private Long userId;

	@Column(unique = true)
	private String username;

	@JsonIgnore
	@Column(name = "password", length = 100)
	private String password;

	@Column(name = "nickname", length = 50)
	private String nickname;

	@JsonIgnore
	@Column(name = "activated")
	private boolean activated;

	@ManyToMany
	@JoinTable( name = "user_authority",
		joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
		inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
	private Set<Authority> authorities;


}