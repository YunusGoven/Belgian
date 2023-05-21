package client;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

// 1
// WAIT CARD CONNECTION
// GENERATE KEYPAIR

// 2
// CONNECT TO THE ACS
// SEND PUBLIC KEY + CLIENT NUMBER TO ACS
// WAIT DIGEST FROM ACS
// SIGN DIGEST WITH PRIVATE KEY OF SIGNATURE/AUTH CRT
// SEND SIGNATURE + PUBLIC KEY OF SIGNATURE/AUTH CRT
public class SimpleClient {

    public SimpleClient(KeyPair keyPair, X509Certificate x509Certificate, PrivateKey privateKey, PublicKey publicKey) {
        this.keyPair = keyPair;
        this.x509Certificate = x509Certificate;
        this.authPrivateKey = privateKey;
        this.authPublicKey = publicKey;
    }

    private SSLSocket sslSocket = null;
    private BufferedReader bufferedReader;
    private PrintWriter printWriter;
    private KeyStore keystore;
    private KeyPair keyPair;
    private X509Certificate x509Certificate;
    private PrivateKey authPrivateKey;
    private PublicKey authPublicKey;
    private final String delimiter = "#BEDRINK#";

    public void init(InetAddress ip, int port) {
        try {
            //TODO
            keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream("src/main/resources/acs_auth_server.p12"), "dalgov".toCharArray());
            KeyManagerFactory kf = KeyManagerFactory.getInstance("SUNX509");

            kf.init(keystore, "dalgov".toCharArray());
            TrustManagerFactory t = TrustManagerFactory.getInstance("X509");
            t.init(keystore);

            SSLContext sc = SSLContext.getInstance("SSL");
            TrustManager[] tm = t.getTrustManagers();
            sc.init(kf.getKeyManagers(), tm, null);
            SSLSocketFactory ssf = sc.getSocketFactory();

            this.sslSocket = (SSLSocket)ssf.createSocket(ip, port);
            this.sslSocket.startHandshake();
            System.out.println("Connection successful to ["+ sslSocket.getInetAddress().getHostAddress()+":"+port+ "]");
            bufferedReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), Charset.forName("UTF-8")));
            printWriter = new PrintWriter(sslSocket.getOutputStream(), true);
        } catch (Exception e) {
            e.printStackTrace();
            close();
            System.out.println("Connection not successful to ["+ ip.getHostAddress()+":"+port+ "]");
        }
    }

    public void close() {
        try {
            sslSocket.close();
            bufferedReader.close();
            printWriter.close();
        } catch (Exception e){}
    }

    // ----------------------- Send Client Data --------------------------
    public boolean sendKeyAndClientNumber(PublicKey idPublicKey, String clientNumber) throws Exception {
        String pubkeyString = Base64.getEncoder().encodeToString(idPublicKey.getEncoded());
        String realPubkeyString = Base64.getEncoder().encodeToString(authPublicKey.getEncoded());
        String fullMessage = pubkeyString + delimiter + clientNumber + delimiter + realPubkeyString;
        byte[] encrypted = encrypt(fullMessage);
        return sendMessage(encrypted);
    }

    private boolean sendMessage(byte[] encryptedByte) {
        String encryptedString = Base64.getEncoder().encodeToString(encryptedByte);
        printWriter.println(encryptedString);
        printWriter.flush();
        System.out.println("Message is successfully");
        return true;
    }

    private byte[] encrypt(String message) throws Exception{
        SecretKey key = getKeyFromPassword(getDHKey(), "someSalt");
        IvParameterSpec iv = generateIv();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] messageArray = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted =  cipher.doFinal(messageArray);
        return encrypted;
    }
    public SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
    public IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        return new IvParameterSpec(iv);
    }
    private String getDHKey() {
        int prime = 23;
        int base = 9;
        int secret = 4;
        try {
            printWriter.println(prime);
            printWriter.flush();
            printWriter.println(base);
            printWriter.flush();
            double A = ((Math.pow(base, secret)) % prime);
            printWriter.println(Double.toString(A));
            printWriter.flush();
            double serverB = Double.parseDouble(bufferedReader.readLine());
            double Adash = ((Math.pow(serverB, secret)) % prime);
            MessageDigest mg = MessageDigest.getInstance("SHA-1");
            mg.update(Double.toString(Adash).getBytes(StandardCharsets.UTF_8));
            byte[] arr = mg.digest();
            return Base64.getEncoder().encodeToString(arr).substring(0,25);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ----------------------- Read Challenge --------------------------
    public String readResponse() throws Exception {
        String challengeEncrypted = readLine();
        byte [] decryptedChallengeByte = decrypt(challengeEncrypted, keyPair.getPrivate());
        String decryptedString = new String(decryptedChallengeByte);
        return decryptedString;
    }
    private String readLine() throws Exception{
        return bufferedReader.readLine();
    }
    private byte [] decrypt(String message, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] messageArray = Base64.getDecoder().decode(message);
        return cipher.doFinal(messageArray);
    }


    // ----------------------- Signature --------------------------

    public boolean signChallengeAndSend(String challenge) throws Exception {
        byte[] challengeArray = challenge.getBytes();
        String algorithm = x509Certificate.getSigAlgName();
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(authPrivateKey);
        signature.update(challengeArray);
        byte[] sign = signature.sign();
        String signatureString = Base64.getEncoder().encodeToString(sign);
        String fullMessage = signatureString + delimiter + algorithm;
        return sendMessage(fullMessage.getBytes());
    }


}
