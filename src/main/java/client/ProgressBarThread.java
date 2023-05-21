package client;

import javax.swing.*;

import static java.lang.Thread.sleep;

public class ProgressBarThread implements Runnable {
    private JProgressBar pg;
    private JTextField status;
    private JTextField challenge;
    private  JButton copyBtn;
    private String numClient;
    public ProgressBarThread(JProgressBar pg, JTextField status, JTextField challenge, JButton copyBtn, String numClient) {
        this.pg= pg;
        this.status = status;
        this.challenge = challenge;
        this.copyBtn = copyBtn;
        this.numClient = numClient;
    }

    @Override
    public void run() {
        pg.setIndeterminate(true);

        // Code to establish contact ACS
        try {
            sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        try {
            SimpleClientInt simpleClientInt = new SimpleClientInt();
            simpleClientInt.init();
            SimpleClient simpleClient = simpleClientInt.getSimpleClient();
            String email = numClient;
            if(simpleClient.sendKeyAndClientNumber(simpleClientInt.getPublicKey(), email)) {
                String challengeReceive = simpleClient.readResponse();
                if (challengeReceive.equals("USER NOT EXIST")) {
                    pg.setIndeterminate(false);
                    pg.setValue(100);
                    status.setText("ERROR");
                    challenge.setText("USER NOT EXIST");
                    copyBtn.setEnabled(false);
                } else {
                    if (simpleClient.signChallengeAndSend(challengeReceive)) {
                        String resp2 = simpleClient.readResponse();
                        if (resp2.equals("SIGNATURE VALID")) {
                            pg.setIndeterminate(false);
                            pg.setValue(100);
                            status.setText("Challenge received");
                            challenge.setText(challengeReceive);
                            copyBtn.setEnabled(true);
                        } else {
                            pg.setIndeterminate(false);
                            pg.setValue(100);
                            status.setText("ERROR");
                            challenge.setText("SIGNATURE NOT VALID");
                            copyBtn.setEnabled(false);
                        }
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }




    }
}
