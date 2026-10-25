package com.fptaptech.catalog.config;

import com.fptaptech.catalog.util.PemUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class JwkKeyManager {

    @Value("${app.jwt.active-kid:catalog-key-2}")
    private String activeKid;

    @Value("${app.jwt.public-key}")
    private Resource activePublicKeyResource;

    @Value("${app.jwt.private-key}")
    private Resource activePrivateKeyResource;

    @Value("${app.jwt.old-public-key}")
    private Resource oldPublicKeyResource;

    @Value("${app.jwt.old-private-key}")
    private Resource oldPrivateKeyResource;

    private final Map<String, RSAKey> keyStore = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        try {
            RSAPublicKey activePub = PemUtils.readPublicKey(activePublicKeyResource);
            RSAPrivateKey activePriv = PemUtils.readPrivateKey(activePrivateKeyResource);
            RSAKey activeRsaKey = new RSAKey.Builder(activePub)
                    .privateKey(activePriv)
                    .keyID(activeKid)
                    .build();
            keyStore.put(activeKid, activeRsaKey);

            RSAPublicKey oldPub = PemUtils.readPublicKey(oldPublicKeyResource);
            RSAPrivateKey oldPriv = PemUtils.readPrivateKey(oldPrivateKeyResource);
            RSAKey oldRsaKey = new RSAKey.Builder(oldPub)
                    .privateKey(oldPriv)
                    .keyID("catalog-key-1")
                    .build();
            keyStore.put("catalog-key-1", oldRsaKey);
        } catch (Exception e) {
            throw new IllegalStateException("Không thể nạp RSA keys: " + e.getMessage(), e);
        }
    }

    public String getActiveKid() {
        return activeKid;
    }

    public synchronized void setActiveKid(String newKid) {
        if (!keyStore.containsKey(newKid)) {
            throw new IllegalArgumentException("Key ID không tồn tại: " + newKid);
        }
        this.activeKid = newKid;
    }

    public RSAKey getActiveKey() {
        RSAKey key = keyStore.get(activeKid);
        if (key == null) {
            throw new IllegalStateException("Active key không tồn tại cho kid: " + activeKid);
        }
        return key;
    }

    public RSAKey getKey(String kid) {
        return keyStore.get(kid);
    }

    public JWKSet getPublicJwkSet() {
        List<JWK> publicKeys = new ArrayList<>();
        for (RSAKey rsaKey : keyStore.values()) {
            publicKeys.add(rsaKey.toPublicJWK());
        }
        return new JWKSet(publicKeys);
    }

    public JWKSet getAllKeysJwkSet() {
        return new JWKSet(new ArrayList<>(keyStore.values()));
    }
}
