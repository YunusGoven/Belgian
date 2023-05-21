package client;

import javax.swing.*;
import java.awt.*;

public class Main extends JFrame{
    public static void main(String[] args) {

//        JFrame j = new JFrame("App");
//        j.setContentPane(new welcomeLayout().getMain());
//        j.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        j.setMinimumSize(new Dimension(400,400));
//        j.setSize(400 ,400);
//        j.pack();
//        j.setVisible(true);
        new Main();
    }


    JPanel parentPanel = new JPanel();
    JPanel welcomePanel = new welcomeLayout(this).getMain();

    JPanel appPanel = new chaApp().getMain();

    public Main() {

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        parentPanel.add(welcomePanel);
        setMinimumSize(new Dimension(400,400));
        setSize(400 ,400);
        add(parentPanel);
        pack();
        setVisible(true);
    }

    public void changeApp() {
        parentPanel.remove(welcomePanel);
        parentPanel.add(appPanel);
        parentPanel.revalidate();
        parentPanel.repaint();
        pack();
    }
    public void changeWelcome() {
        parentPanel.remove(appPanel);
        parentPanel.add(welcomePanel);
        parentPanel.revalidate();
        parentPanel.repaint();
        pack();
    }



}
