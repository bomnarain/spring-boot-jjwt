package kr.co.ggoom.jjwt.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import kr.co.ggoom.jjwt.entity.User;
import kr.co.ggoom.jjwt.repository.UserRepository;
import lombok.AllArgsConstructor;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * 
 * JwtTokenProvider가 제공한 사용자 정보로 DB에서 알맞은 사용자 정보를 가져와 UserDetails 생성
 * @author Bomnarain
 *
 */
@AllArgsConstructor
@Component
@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
	
private final Logger log = LoggerFactory.getLogger(this.getClass());
	
   private final UserRepository userRepository;
   
   /* @AllArgsConstructor 어노테이션 사용으로 아래 코드가 필요 없어짐 
   public CustomUserDetailsService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }
   */

   @Override
   @Transactional
	public UserDetails loadUserByUsername(final String username) {
	   log.debug("CustomUserDetailsService::loadUserByUsername(username : {}) 실행", username);
	   // 확인용
	   Optional<User> member = userRepository.findOneWithAuthoritiesByUsername(username);
	   if ( member.isPresent() ) {
		   log.debug("memeber : {}", member.toString());
	   } else {
		   log.debug("memeber : 정보없음");
		   throw new UsernameNotFoundException("UsernameNotFoundException");
	   }
	   // 확인용
	   return userRepository.findOneWithAuthoritiesByUsername(username)
			   .map(user -> createUser(username, user))
			   .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
   }

   private org.springframework.security.core.userdetails.User createUser(String username, User user) {
	   log.debug("createUser");
      if (!user.isActivated()) {
         throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
      }
      log.debug("권한(grantedAuthorities) 리스트화  시작");
      List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
              .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
              .collect(Collectors.toList());
      log.debug("권한(grantedAuthorities) : {} ", grantedAuthorities.toString());
      return new org.springframework.security.core.userdetails.User(user.getUsername(),
              user.getPassword(),
              grantedAuthorities);
   }
}
