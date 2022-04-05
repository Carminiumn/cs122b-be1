package com.github.klefstad_teaching.cs122b.idm;

import com.github.klefstad_teaching.cs122b.core.spring.StackService;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@StackService
@EnableConfigurationProperties({
    IDMServiceConfig.class
})
public class IDMService
{
    public static void main(String[] args)
    {
        SpringApplication.run(IDMService.class, args);
    }
}
