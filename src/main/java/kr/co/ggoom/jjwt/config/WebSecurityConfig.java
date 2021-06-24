package kr.co.ggoom.jjwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import kr.co.ggoom.jjwt.jwt.JwtAccessDeniedHandler;
import kr.co.ggoom.jjwt.jwt.JwtAuthenticationEntryPoint;
import kr.co.ggoom.jjwt.jwt.JwtAuthenticationFilter;
import kr.co.ggoom.jjwt.jwt.JwtSecurityConfig;
import kr.co.ggoom.jjwt.service.CustomUserDetailsService;
import kr.co.ggoom.jjwt.jwt.JwtTokenProvider;

/**
 * 
 * Spring Security 관련 설정들을 하는 Configuration 클래스
 * @author Bomnarain
 *
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		securedEnabled = true, // @Secured 애노테이션을 사용하여 인가 처리를 하고 싶을때 사용하는 옵션이다. 기본값 false
        jsr250Enabled = true, // @RolesAllowed 애노테이션을 사용하여 인가 처리를 하고 싶을때 사용하는 옵션이다. 기본값 false
		prePostEnabled = true // @PreAuthorize, @PostAuthorize 애노테이션을 사용하여 인가 처리를 하고 싶을때 사용하는 옵션이다. 기본값 false
)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 
	@Autowired
    private CustomUserDetailsService customUserDetailService;
    
    @Autowired
    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    
    @Autowired
    public JwtAuthenticationFilter jwtAuthenticationFilter;
    
    private final JwtTokenProvider jwtTokenProvider;
    private final CorsFilter corsFilter;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public WebSecurityConfig(
            JwtTokenProvider jwtTokenProvider,
            CorsFilter corsFilter,
            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }
    
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
    @Bean
    // BCryptPasswordEncoder는 Spring Security에서 제공하는 비밀번호 암호화 객체입니다.
    // Service에서 비밀번호를 암호화할 수 있도록 Bean으로 등록합니다.    
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                        ,"/error"
                )
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // js, css, image 설정은 보안 설정의 영향 밖에 있도록 만들어주는 설정.
    }
    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
    	auth.userDetailsService(customUserDetailService);
    }
    
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
    	
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
                .csrf().disable()

                .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // custom하여 만든 jwtAuthenticationEntryPoint
                .accessDeniedHandler(jwtAccessDeniedHandler) // custom하여 만든 jwtAccessDeniedHandler 

                // enable h2-console : 데이터 확인을 위해 사용하고 있는 h2-console을 위한 설정을 추가
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()	// 요청에 의한 보안검사 시작
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()

                .anyRequest().authenticated()	//어떤 요청에도 보안검사를 한다.
                .and()
                .apply(new JwtSecurityConfig(jwtTokenProvider))
                
                .and()
                .rememberMe().key("uniqueAndSecret");
        
        httpSecurity.antMatcher("/api").addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
    
}

