package br.com.devaoc.security.filter;

import br.com.devaoc.core.model.ApplicationUser;
import br.com.devaoc.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor(onConstructor =  @__(@Autowired))
@Slf4j
public class JwtUserNameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager ;
    private final JwtConfiguration jwtConfiguration;

// metodo que tentara fazer a autenticacao do usuario, delegando a responsabilidade para
    // userDetailService
    @Override
    @SneakyThrows //encapsula em uma excecao do tipo runtime
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("Attempting authentication ...");
        ApplicationUser applicationUser =  new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if(applicationUser == null){
            throw new UsernameNotFoundException("Unable to retrieve the username or password");
        }

        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadUserByUserName ", applicationUser.getUsername() );

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), Collections.emptyList());
        usernamePasswordAuthenticationToken.setDetails(applicationUser);
        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("Authentication was successful for the user '{}', generating JWE token ", authResult.getName());

        SignedJWT signedJWT = createSignedJWT(authResult);
        String encryptToken = encryptToken(signedJWT);

        log.info("Token generated succesfully, adding it ot the response header");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, "+ jwtConfiguration.getHeader().getName());
        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptToken);

    }

    //criar um json assinado..
    // qdo vc esta criptografando um token, primeiro vc assina e depois criptografa
    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth){
        log.info("Starting to create the signed JWT");
        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();
        JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, applicationUser);
        //agora nós já temos as nossas claims, precisamos criptografar e assinar o nosso token..

        KeyPair rsaKeys = generateKeyPair();

        log.info("Building JWK from the RSA Keys");

        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk)
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimSet);

        log.info("Signing the token with the private RSA Key");

        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());
        signedJWT.sign(signer);

        log.info("Serialized token '{}'", signedJWT.serialize());

        return signedJWT;

    }

    //assistir o curso sobre spring essencials - jwt.io para ver template de claims a serem criados
    // tem que conter tudo aquilo que pode ser utilizado pelos outros microsservicos
    private JWTClaimsSet createJWTClaimSet(Authentication auth, ApplicationUser applicationUser){
        log.info("Creating the JwtClaimSet Object for '{}'", applicationUser);
        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(toList()))
                .issuer("http://academy.devaoc")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair(){
        log.info("Generating RSA 2048 bits Keys");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.genKeyPair();
    }


    private String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptToken mehtod");
        DirectEncrypter directDecrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));
        log.info("Encrypting token with system's private key");
        jweObject.encrypt(directDecrypter);

        log.info("Token encrypted");
        return jweObject.serialize();
    }
}

// nessa classe, faremos a autenticacao
// gerar o token, assinar o tokem, criptografar o token e depois retornar pra quem estiver chamando
