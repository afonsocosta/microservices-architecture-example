package br.com.devaoc.security.config;

import br.com.devaoc.core.property.JwtConfiguration;
import br.com.devaoc.security.filter.JwtUserNameAndPasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.config.http.SessionCreationPolicy.*;

@EnableWebSecurity
@RequiredArgsConstructor(onConstructor =  @__(@Autowired))
public class SecurityCredentialsConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final JwtConfiguration jwtConfiguration;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
                    .sessionManagement().sessionCreationPolicy(STATELESS)
                .and()
                    .exceptionHandling().authenticationEntryPoint((req, resp, e) -> resp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                    .addFilter(new JwtUserNameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration))
                .authorizeRequests()
                    .antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                    .antMatchers("/api-example/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated();
        }

    // metodo que faz autenticacao chamando findByUserName
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
