package client;


import javax.smartcardio.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class TerminalCarteConnector implements Runnable {

    private Main carteApp;
    public TerminalCarteConnector(Main carteApp) {
        this.carteApp = carteApp;
    }

    private boolean isVirtual(List<CardTerminal> terminalList) {
        String javacos0 = "JAVACOS Virtual Contact Reader 0";
        String javacos1 = "JAVACOS Virtual Contactless Reader 1";
        int nbJavaCosInList = (int) terminalList.stream().filter(cardTerminal -> cardTerminal.getName().equals(javacos0) || cardTerminal.getName().equals(javacos1)).count();
        return terminalList.size() == nbJavaCosInList;
    }

    @Override
    public void run() {
        try {
            // Créer le terminal de carte
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminals terminals = factory.terminals();

            // Attendre la présence d'une carte
            System.out.println("En attente de la présence d'une carte...");
            List<CardTerminal> terminalsList = terminals.list();
            if (terminalsList.isEmpty() || isVirtual(terminalsList)) {
                System.err.println("Aucun lecteur de carte trouvé.");
            }
            CardTerminal cardTerminal = terminalsList.get(0);
            detecterCarteConnectee(cardTerminal);
        } catch (Exception e) {

        }

    }

    private void detecterCarteConnectee(CardTerminal cardTerminal) {
        while (true) {
            try {

                boolean cardPresent = cardTerminal.waitForCardPresent(0);

//                Card card = cardTerminal.connect("*");
//
//                CommandAPDU selectCommand = new CommandAPDU(
//                        (byte) 0x00,
//                        (byte) 0xA4,
//                        (byte) 0x04,
//                        (byte) 0x00,
//                        new byte[] { (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x30, (byte) 0x29, (byte) 0x05, (byte) 0x70, (byte) 0x00, (byte) 0xAD, (byte) 0x13, (byte) 0x10, (byte) 0x01, (byte) 0x01, (byte) 0xFF}
//                );
//
//                ResponseAPDU selectResponse = card.getBasicChannel().transmit(selectCommand);
//                if (selectResponse.getSW() != 0x9000) {
//                    // Handle error condition
//                }
//                // --------------
//                CommandAPDU getCardDataCommand = new CommandAPDU(
//                        (byte) 0x80,
//                        (byte) 0xE6,
//                        (byte) 0x00,
//                        (byte) 0x00
//                ); // Exemple de commande pour lire les 256 premiers octets de données
//                ResponseAPDU getCardDataResponse = card.getBasicChannel().transmit(getCardDataCommand); // Envoyer la commande à la carte
//                var a = getCardDataResponse.getData();
//                var s = new String(a);
//
//                // ------------
//                CommandAPDU command = new CommandAPDU(
//                        (byte) 0x00,
//                        (byte) 0xC0,
//                        (byte) 0x00,
//                        (byte) 0x00,
//                        (byte) 0x03
//                ); // Exemple de commande pour lire les 256 premiers octets de données
//                ResponseAPDU response = card.getBasicChannel().transmit(command); // Envoyer la commande à la carte
//                System.out.println(response);

                if (cardPresent) {
                    carteApp.changeApp();
                    cardTerminal.waitForCardAbsent(0);
                   carteApp.changeWelcome();
                }
            } catch (Exception e) {
                System.err.println("Une erreur s'est produite lors de l'attente de la carte");
            }
        }
    }
}
