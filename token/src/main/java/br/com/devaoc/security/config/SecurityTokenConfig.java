package br.com.devaoc.security.config;

import br.com.devaoc.core.property.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@RequiredArgsConstructor(onConstructor =  @__(@Autowired))
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

    protected final JwtConfiguration jwtConfiguration;

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
                .authorizeRequests()
                    .antMatchers(jwtConfiguration.getLoginUrl()).permitAll()
                    .antMatchers("/api-example/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated();
        }


}
