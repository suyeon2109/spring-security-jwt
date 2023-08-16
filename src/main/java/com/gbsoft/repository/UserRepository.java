package com.gbsoft.repository;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.gbsoft.domain.User;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class UserRepository {

	private final EntityManager em;

	public Optional<User> findOneWithAuthoritiesByUsername(String username) {
		try{
			User user = em.createQuery("select u from User u where u.username = :username", User.class)
				.setParameter("username", username)
				.getSingleResult();
		    return Optional.of(user);
	    } catch (NoResultException e) {
		    return Optional.empty();
	    }
	}

	public User save(User user) {
		em.persist(user);
		return user;
	}
}
