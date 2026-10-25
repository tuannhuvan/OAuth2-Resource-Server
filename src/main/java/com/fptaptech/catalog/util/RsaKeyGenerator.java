package com.fptaptech.catalog.util;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class RsaKeyGenerator {

    public static void main(String[] args) throws Exception {
        File dir = new File("src/main/resources/keys");
        if (!dir.exists()) {
            dir.mkdirs();
        }

        generateKeyPair("catalog-key-1", dir);
        generateKeyPair("catalog-key-2", dir);
        
        // Also copy catalog-key-2 as app.key and app.pub for default compatibility
        copyFile(new File(dir, "catalog-key-2.key"), new File(dir, "app.key"));
        copyFile(new File(dir, "catalog-key-2.pub"), new File(dir, "app.pub"));
        System.out.println("RSA Keys generated successfully in " + dir.getAbsolutePath());
    }

    private static void copyFile(File src, File dest) throws Exception {
        java.nio.file.Files.copy(src.toPath(), dest.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    public static void generateKeyPair(String keyId, File dir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();

        File privFile = new File(dir, keyId + ".key");
        File pubFile = new File(dir, keyId + ".pub");

        try (FileWriter writer = new FileWriter(privFile, StandardCharsets.UTF_8)) {
            writer.write("-----BEGIN PRIVATE KEY-----\n");
            writer.write(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded()));
            writer.write("\n-----END PRIVATE KEY-----\n");
        }

        try (FileWriter writer = new FileWriter(pubFile, StandardCharsets.UTF_8)) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(publicKey.getEncoded()));
            writer.write("\n-----END PUBLIC KEY-----\n");
        }
    }
}
