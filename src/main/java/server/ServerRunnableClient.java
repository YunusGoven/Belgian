package server;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ServerRunnableClient implements Runnable{

    private Socket client;
    private PrivateKey serverPrivateKey;
    private BufferedReader bufferedReader;
    private PrintWriter printWriter;

    private final String delimiter = "#BEDRINK#";


    public ServerRunnableClient(Socket client, PrivateKey serverPrivateKey) throws Exception{
        this.client = client;
        bufferedReader = new BufferedReader(new InputStreamReader(client.getInputStream(), Charset.forName("UTF-8")));
        printWriter = new PrintWriter(client.getOutputStream(), true);
        this.serverPrivateKey = serverPrivateKey;
    }

    @Override
    public void run() {
        try {
            String received = readKeyAndClientNumber();
            if (!"exit".equals(received)) {
                String[] array = received.split(delimiter);
                String pubkey = array[0];
                PublicKey clientPublicKey = generatePublicKey(pubkey);
                String clientNumber = array[1];
                String realAuthPublicKey = array[2];
                if (clientExist(clientNumber)) {
                    String code = sendCode(clientPublicKey);
                    boolean isok = checkSignature(code, realAuthPublicKey);
                    if (!isok) {
                        byte[] encrypted = encrypt("SIGNATURE NOT VALID", clientPublicKey);
                        sendMessage(encrypted);
                        close();
                    } else {
                        byte[] encrypted = encrypt("SIGNATURE VALID", clientPublicKey);
                        sendMessage(encrypted);
                        close();
                    }
                } else {
                    byte[] encrypted = encrypt("USER NOT EXIST", clientPublicKey);
                    sendMessage(encrypted);
                    close();
                }
            } else {
                close();
            }
            close();
        } catch (Exception e) {
            e.printStackTrace();
            close();
        }
    }


    // --------------- read client number + public key + decrypt
    private String readKeyAndClientNumber() throws Exception {
        byte[] decryptedByte = decrypt();
        String decryptedString = new String(decryptedByte);
        return decryptedString;

    }
    private String readLine() throws Exception {
        return bufferedReader.readLine();
    }
    private byte[] decrypt() throws Exception{
        SecretKey key = getKeyFromPassword(getDHKey(), "someSalt");
        IvParameterSpec iv = generateIv();
        String message = readLine();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] arr = Base64.getDecoder().decode(message);
        return cipher.doFinal(arr);
    }

    public static SecretKey getKeyFromPassword(String password, String salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
    private String getDHKey() {
        double prime, base, clientPublicKey, serverPublicKey, secretEncryptionKey;
        int secret = 3;

        try {
            prime = Double.parseDouble(bufferedReader.readLine());
            base = Double.parseDouble(bufferedReader.readLine());
            clientPublicKey = Double.parseDouble(bufferedReader.readLine());
            serverPublicKey = ((Math.pow(base, secret)) % prime);
            printWriter.println(Double.toString(serverPublicKey));
            secretEncryptionKey = ((Math.pow(clientPublicKey, secret)) % prime);
            printWriter.flush();
            MessageDigest mg = MessageDigest.getInstance("SHA-1");
            mg.update(Double.toString(secretEncryptionKey).getBytes(StandardCharsets.UTF_8));
            byte[] arr = mg.digest();
            return Base64.getEncoder().encodeToString(arr).substring(0,25);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        return new IvParameterSpec(iv);
    }

    // --------------- encrypt + send
    private byte[] encrypt(String message, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }
    private boolean sendMessage(byte[] encryptedByte) {
        String encryptedString = Base64.getEncoder().encodeToString(encryptedByte);
        printWriter.println(encryptedString);
        printWriter.flush();
        System.out.println("Message is successfully");
        return true;
    }

    // ---------- generate public key
    private PublicKey generatePublicKey(String publicKeyString) throws Exception{
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        return publicKey;
    }


    // --------------------  verify user exit
    public boolean clientExist(String clientNumber) {
        String token = getTokenAccess();
        if (token == null) return false;
        int code = getCodeUserExist(token, clientNumber);
        return code == 409;

    }

    private String getTokenAccess() {
        try {
            var client = HttpClient.newHttpClient();

            var request = HttpRequest.newBuilder(
                            URI.create("https://api.bedrink.be/v1/Token/TokenAccess"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            JsonObject jsonObject = new JsonParser().parse(response.body()).getAsJsonObject();
            JsonElement jsonElement =  jsonObject.get("data");
            JsonElement jsonToken = jsonElement.getAsJsonObject().get("access");

            String token = jsonToken.getAsString();
            return token;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private int getCodeUserExist(String token, String email) {
        try {
            var client = HttpClient.newHttpClient();var request = HttpRequest.newBuilder(
                            URI.create("https://api.bedrink.be/v1/Authentication/Unique/"+ email))
                    .header("Authorization", "Bearer "+token)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int code = response.statusCode();
            return code;
        } catch (Exception e){
            e.printStackTrace();
            return 204;
        }
    }

    // ---------- generate challenge + send
    private String genCode() {
        String generatedString = UUID.randomUUID().toString();
        return generatedString;
    }

    private String sendCode(PublicKey publicKey) throws Exception {
        String challenge = genCode();
        byte[] encryptedChallenge = encrypt(challenge, publicKey);
        sendMessage(encryptedChallenge);
        return challenge;
    }

    // ------------ Signature
    private boolean checkSignature(String code, String realAuthPublicKey) throws Exception {
        PublicKey authPublicKey = generatePublicKey(realAuthPublicKey);
        String receive = readLine();
        byte[] arr = Base64.getDecoder().decode(receive);
        receive = new String(arr);
        String[] splitted = receive.split(delimiter);
        String signature = splitted[0];
        String algo = splitted[1];
        byte[] signatureByte = Base64.getDecoder().decode(signature);
        byte[] codeByte = code.getBytes();

        Signature s = Signature.getInstance(algo);
        s.initVerify(authPublicKey);
        s.update(codeByte);
        boolean ok = s.verify(signatureByte);
        return  ok;
    }

    private void close(){
        try {
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
            try {
                client.close();
            } catch (Exception ex) {
            }
        }
    }
}
