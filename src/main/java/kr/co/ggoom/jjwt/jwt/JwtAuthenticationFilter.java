package kr.co.ggoom.jjwt.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import kr.co.ggoom.jjwt.service.CustomUserDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * 
 * Jwt가 유효한 토큰인지 인증하기 위한 Filter
 * @author Bomnarain
 * OncePerRequestFilter는 그 이름에서도 알 수 있듯이 모든 서블릿에 일관된 요청을 처리하기 위해 만들어진 필터이다.
 * 이 추상 클래스를 구현한 필터는 사용자의 한번 요청 당 딱 한번만 실행되는 필터를 만들 수 있다.
 * ------------------------------------------------------------------------------------------------------------------------------------------
 * Spring Security에서 인증과 접근 제어 기능이 Filter로 구현되어진다.
 * 이러한 인증과 접근 제어는 RequestDispatcher 클래스에 의해 다른 서블릿으로 dispatch되게 되는데, 이 때 이동할 서블릿에 도착하기 전에 다시 한번 filter chain을 거치게 된다.
 * 바로 이 때 또 다른 서블릿이 우리가 정의해둔 필터가 Filter나 GenericFilterBean로 구현된 filter를 또 타면서 필터가 두 번 실행되는 현상이 발생할 수 있다.
 * 이런 문제를 해결하기 위해 등장한 것이 바로 이번 글의 주인공인 OncePerRequestFilter이다.
 * 
 * Filter 는 JwtAuthenticationFilter 를 만들어서 WebSecurityConfigure::config(HttpSecurity httpSecurity) 메소드에서 pre-filter 로 동작하게 된다.
 * 해당 Filter 에서 Authentication 도 수행된다.
 * 
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	Logger logger = LoggerFactory.getLogger(this.getClass());
	
	@Autowired 
	private JwtTokenProvider jwtTokenProvider;
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	
	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String BEARER_PREFIX = "Bearer ";
	
	public JwtAuthenticationFilter(JwtTokenProvider jwtProvider) {
		logger.debug("실행 : JwtAuthenticationFilter ");
		jwtTokenProvider = jwtProvider;
	}
	
	// Request로 들어오는 Jwt Token의 유효성을 검증하는 filter를 filterChain에 등록합니다.
	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 
			throws ServletException, IOException {
		logger.debug("실행 doFilterInternal");
		try { 
			// 헤더에서 JWT 받아옴
			String token = this.resolveToken(request);
			// 유효한 토큰인지 확인
			if (token != null && jwtTokenProvider.validateToken(token)) {
				String userName = jwtTokenProvider.getAuthentication(token).getName();
				logger.debug("token 에서 가지고 온 userName : {}", userName);
				UserDetails userDetails = customUserDetailsService.loadUserByUsername(userName);
				logger.debug("userDetails : {}",userDetails.toString());
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));		
				// SecurityContext에 Authentication 객체를 저장
				SecurityContextHolder.getContext().setAuthentication(authentication);
				logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), request.getRequestURI());
			} else {
				logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", request.getRequestURI());
			}
		} catch (Exception e) { 
			logger.error("Could not set user authentication in security context : {}", e); 
		} 
		// 여기까지 전처리
		filterChain.doFilter(request, response);
		// 여기부터 후처리
	}
	
	// Request header 에서 토큰 정보를 꺼내오기
	private String resolveToken(HttpServletRequest request) {
		String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith(BEARER_PREFIX)) {
			return headerAuth.substring(7, headerAuth.length());
		}
		return null;
	}   
}
