package client;

import javax.swing.*;

public class welcomeLayout {
    public JPanel getMain() {return main;}

    private JPanel main;
    private JLabel imageLabel;

    public welcomeLayout(Main main) {
        Thread carteConnector = new Thread(new TerminalCarteConnector(main));
        carteConnector.start();

    }

}
