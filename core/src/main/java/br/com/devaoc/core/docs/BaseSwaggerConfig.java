package br.com.devaoc.core.docs;

import org.springframework.context.annotation.Bean;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

public class BaseSwaggerConfig {

    private final String basePackage;

    public BaseSwaggerConfig(String basePackage){
        this.basePackage = basePackage;
    }

    public Docket api(){
        return new Docket(DocumentationType.SWAGGER_2)
                .select()
                .apis(RequestHandlerSelectors.basePackage(basePackage))
                .build()
                .apiInfo(metaData());
    }

    @Bean
    public ApiInfo metaData(){
        return new ApiInfoBuilder()
                .title("Creating a micro service arquitecture")
                .description("Configuring swagger lib")
                .version("1.0")
                .contact(new Contact("Afonso", "devaoc.com.br", "devaoc@gmail.com"))
                .license("Private stuff bro, belongs to Devaoc")
                .licenseUrl("http://devaoc.com.br")
               .build();
    }

}
