package smartcard;

import java.util.Arrays;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class CardReaderTest {
        /**
         * Lists available card terminals (readers).
         */
        public static void main(String[] args)
        throws CardException {
                TerminalFactory terminalFactory = TerminalFactory.getDefault();
                List<CardTerminal> terminals = terminalFactory.terminals().list();
                System.out.println(terminals.size() + " terminal(s) found");
                for (CardTerminal terminal : terminals) {
                        System.out.println(terminal + " " + (!terminal.isCardPresent() ? "No " : "") + " Card Present");
                }
                
                CardTerminal terminal = terminals.get(0);
                System.out.println("terminal: " + terminal);
                Card card = terminal.connect("T=0");
                System.out.println("card: " + card);
                CardChannel channel = card.getBasicChannel();
                System.out.println("channel: " + channel);
                ResponseAPDU r = channel.transmit(new CommandAPDU(new byte[0]));
                System.out.println("response: " + Arrays.toString(r.getBytes()));
                // disconnect
                card.disconnect(false);
        }
}
