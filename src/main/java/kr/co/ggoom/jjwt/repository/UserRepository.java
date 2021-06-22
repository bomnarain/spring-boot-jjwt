package kr.co.ggoom.jjwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import kr.co.ggoom.jjwt.entity.User;

public interface UserRepository  extends JpaRepository<User, Long>{
	
	@EntityGraph(attributePaths = "authorities")
	Optional<User> findOneWithAuthoritiesByUsername(String username);
	
	// username 중복 가입 방지용
	boolean existsByUsername(String username);
}
