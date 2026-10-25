package com.fptaptech.catalog;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
public class OpenApiExportTest {

    @Autowired
    private WebApplicationContext context;

    @Test
    void exportOpenApiYaml() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(context).build();
        MvcResult result = mockMvc.perform(get("/v3/api-docs.yaml"))
                .andExpect(status().isOk())
                .andReturn();

        String yaml = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        File dir = new File("docs/api");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        File target = new File(dir, "openapi.yaml");
        Files.writeString(target.toPath(), yaml, StandardCharsets.UTF_8);
        System.out.println("Exported openapi.yaml to " + target.getAbsolutePath());
    }
}
