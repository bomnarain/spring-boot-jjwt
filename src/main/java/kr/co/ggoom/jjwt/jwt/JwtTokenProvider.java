package kr.co.ggoom.jjwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import kr.co.ggoom.jjwt.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

/**
 * 
 * Jwt Token을 생성, 인증, 권한 부여, 유효성 검사, PK 추출 등의 다양한 기능을 제공하는 클래스
 * @author Bomnarain
 *
 */
@Component
public class JwtTokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";
   //private static final String BEARER_TYPE = "bearer";

   private final String secret;   
   // 토큰 유효시간
   private final long tokenValidityInMilliseconds;
   private final long tokenValidityInMillisecondsForRememberMe;

   private final CustomUserDetailsService userDetailsService;
   
   private Key key;

   public JwtTokenProvider(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds,
      @Value("${jwt.token-validity-in-seconds-for-rememberme}") long tokenValidityInMillisecondsForRememberMe
      ) {
	  logger.debug("JwtTokenProvider 실행");
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000L * 60 * 60; //  설정값 x 1시간만 토큰 유효;
      this.tokenValidityInMillisecondsForRememberMe = tokenValidityInMillisecondsForRememberMe * 1000L * 60 * 60 * 12 * 365; //  설정값 x 365일 토큰 유효;
      this.userDetailsService = null;
      logger.debug("JwtTokenProvider 생성완료");
   }

   @Override
   public void afterPropertiesSet() throws Exception {
      byte[] keyBytes = Decoders.BASE64.decode(secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }

   // Jwt 토큰 생성
   public String createToken(Authentication authentication, boolean rememberMe) {
	   logger.debug("createToken 실행");
	   // 권한들 가져오기
	   String authorities = authentication.getAuthorities().stream()
			   .map(GrantedAuthority::getAuthority)
			   .collect(Collectors.joining(","));
	   logger.debug("authorities : {} ", authorities);
	   Date nowDate  = new Date();
	   long now = (new Date()).getTime();
	   Date validity = new Date(now + this.tokenValidityInMilliseconds);
	   if (rememberMe) {
		   validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
	   } else {
		   validity = new Date(now + this.tokenValidityInMilliseconds);
	   }
	   logger.debug("Jwts.builder().setSubject({})",authentication.getName());
	   return Jwts.builder()
			   .setSubject(authentication.getName())
			   .claim(AUTHORITIES_KEY, authorities) // 정보 저장
			   .setIssuedAt(nowDate) // 토큰 발행 시간 정보
			   .signWith(key, SignatureAlgorithm.HS512)
			   // 사용할 암호화 알고리즘과
			   // signature에 들어갈 secret값 세팅
			   .setExpiration(validity) // set Expire Time
			   .compact();
   }

   // 인증 성공시 SecurityContextHolder에 저장할 Authentication 객체 생성
   public Authentication getAuthentication(String token) {
	   // 토큰 복호화
      Claims claims = Jwts
              .parserBuilder()
              .setSigningKey(key)
              .build()
              .parseClaimsJws(token)
              .getBody();
      /*
      if (claims.get(AUTHORITIES_KEY) == null) {
          throw new RuntimeException("권한 정보가 없는 토큰입니다.");
      }
      */
      logger.debug("claims.get(AUTHORITIES_KEY).toString() : {}",claims.get(AUTHORITIES_KEY).toString());
      // 클레임에서 권한 정보 가져오기
      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      // User 객체를 만들어서 Authentication 리턴
      User principal = new User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }
   
   // Jwt Token의 유효성 및 만료 기간 검사
   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }
}
