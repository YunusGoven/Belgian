package server;

public class ServerRun {

    public static void main(String[] args) {
        SimpleServer simpleServer = new SimpleServer();
        (new Thread(simpleServer)).start();
    }
}
