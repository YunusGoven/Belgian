package client;

import java.net.InetAddress;
import java.security.*;
import java.security.cert.X509Certificate;

public class SimpleClientInt {
    private final String PCS_FILE_CONFIG = "C:\\Users\\Karde\\Desktop\\Belgian\\src\\main\\resources\\pkcs11.cfg";
    private final String ALIAS_KEY_AUTHENTICATION_KEYSTORE = "Authentication";

    private final String alias = "Authentication";
    private SimpleClient simpleClient;
    private PublicKey publicKey;

    public void init() {
        try {
            Provider p = Security.getProvider("SunPKCS11");
            p = p.configure(PCS_FILE_CONFIG);
            Security.addProvider(p);

            KeyStore keyStore = KeyStore.getInstance("PKCS11", p);
            keyStore.load(null, null);

            PublicKey realPublicKey = keyStore.getCertificate(alias).getPublicKey();
            PrivateKey realPrivateKey = (PrivateKey) keyStore.getKey(alias, null);
            X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate(ALIAS_KEY_AUTHENTICATION_KEYSTORE);

            setInfo(x509Certificate);

            //**
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            publicKey = pair.getPublic();
            //**

            simpleClient = new SimpleClient(pair,x509Certificate, realPrivateKey, realPublicKey);
            simpleClient.init(InetAddress.getLocalHost(), 2555);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void setInfo(X509Certificate x509Certificate) {

    }

    public SimpleClient getSimpleClient() {
        return simpleClient;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
}
