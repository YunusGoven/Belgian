package client;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

public class chaApp {
    private JTextField numClient;
    private JButton sendBtn;
    private JTextField challenge;
    private JPanel main;
    private JButton copyBtn;
    private JTextField status;
    private JPanel pg_panel;
    private JProgressBar pg_waiting;
    private JButton clearButton;


    public JPanel getMain() {return main;}

    public chaApp() {

        pg_panel.setVisible(false);
        sendButtonListener();
    }

    public void cardConnected() {
        main.setVisible(true);
    }

    public void cardDisconnect() {
        main.setVisible(false);
    }

    private void sendButtonListener() {
        sendBtn.addActionListener(e -> {
            if (!numClient.getText().isBlank()) {
                status.setText("Waiting ...");
                ProgressBarThread wt = new ProgressBarThread(pg_waiting, status, challenge, copyBtn, numClient.getText());
                pg_waiting.setValue(0);
                pg_panel.setVisible(true);
                (new Thread(wt)).start();
            }
        });
        copyBtn.addActionListener(e -> {
            if (!challenge.getText().isBlank()) {
                StringSelection stringSelection = new StringSelection(challenge.getText());
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(stringSelection, null);
                status.setText("Successfully copied");
            }
        });
        clearButton.addActionListener(e -> {
            challenge.setText("");
            status.setText("");
            pg_waiting.setValue(0);
            pg_panel.setVisible(false);
            copyBtn.setEnabled(false);
            numClient.setText("");
        });
    }
}
