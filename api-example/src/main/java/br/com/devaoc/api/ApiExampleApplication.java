package br.com.devaoc.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
//importante adicionar essas proximas duas linhas para informar ao springboot
//onde ele procurar as entidade e os repositorios após a extração para um módulo separado
@EntityScan({"br.com.devaoc.core.model"})
@EnableJpaRepositories({"br.com.devaoc.core.repository"})
public class ApiExampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiExampleApplication.class, args);
	}

}
