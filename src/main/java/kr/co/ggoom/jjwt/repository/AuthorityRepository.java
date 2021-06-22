package kr.co.ggoom.jjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import kr.co.ggoom.jjwt.entity.Authority;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}

