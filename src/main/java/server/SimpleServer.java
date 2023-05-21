package server;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.PrivateKey;


// WAIT CLIENT CONNECTION
// READ DATA + DECRYPT
// CREATE DIGEST
// ENCRYPT DIGEST
// SEND ENCRYPT DIGEST TO CLIENT
// WAIT FOR SIGNATURE
// READ SIGNATURE + PUBLIC KEY
// CHECK SIGNATURE


public class SimpleServer implements Runnable {

    private SSLServerSocket sslServerSocket;
    private final int PORT_AUTH = 2555;
    private PrivateKey serverPrivateKey;

    @Override
    public void run() {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("src/main/resources/acs_auth_server.p12"), "dalgov".toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SUNX509");
            kmf.init(ks, "dalgov".toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(ks);

            SSLContext sc = SSLContext.getInstance("SSL");
            TrustManager[] trustManagers = tmf.getTrustManagers();
            sc.init(kmf.getKeyManagers(),trustManagers, null);

            SSLServerSocketFactory sslServerSocketFactory = sc.getServerSocketFactory();
            sslServerSocket = (SSLServerSocket)sslServerSocketFactory.createServerSocket(PORT_AUTH);
            System.out.println("[ACS SERVER AUTH ON] Serveur ip: "+ InetAddress.getLocalHost().getHostAddress() +" sur le port : "+PORT_AUTH);
            serverPrivateKey = (PrivateKey) ks.getKey("acs_auth_server", "dalgov".toCharArray());
            loop();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private void loop() {
        while (!sslServerSocket.isClosed()) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("[ACS SERVER AUTH] [Client "+ sslSocket.getInetAddress().getHostAddress()+ "] s'est connecté !");
                ServerRunnableClient sc = new ServerRunnableClient(sslSocket, serverPrivateKey);
                (new Thread(sc)).start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
