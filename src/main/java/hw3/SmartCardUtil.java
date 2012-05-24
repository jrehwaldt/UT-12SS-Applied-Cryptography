package hw3;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/*
 * You do not have to change anything here.
 */

@SuppressWarnings("restriction")
public final class SmartCardUtil {
	/**
	 * Establishes the connection with the Smart Card (if present)
	 * using the first available terminal.
	 */
	public static Card connectCard() throws CardException {
		// Get available terminals
		List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
		if (terminals.size() < 1) {
			throw new CardException("No attached Smart Card terminals found");
		}

		// Search for connected cards
		Card card = null;
		for (CardTerminal terminal : terminals) {
			if (terminal.isCardPresent()) {
				card = terminal.connect("*");
				break;
			}
		}
		if (card == null) {
			throw new CardException("No connected Smart Cards found");
		}

		return card;
	}

	/**
	 * Runs command on this card channel.
	 * 
	 * Be *very* careful with running commands!
	 * Double-check what you are running, in order not to brick the card accidentally.
	 * 
	 * Commands and responses are both known as application protocol data units (APDUs).
	 * Command APDU consists of 4-byte header and 0..255 bytes of data.
	 * Response APDU contains 0..256 bytes of response data and 2-byte status word.
	 * 
	 * See also:
	 * http://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
	 * 
	 * Check this list to decode response status codes:
	 * http://www.wrankl.de/SCTables/SCTables.html#SCRC
	 */
	public static byte[] runCommand(CardChannel channel, CommandAPDU command) throws CardException {
		return runCommand(channel, command, false);
	}

	public static byte[] runCommand(CardChannel channel, CommandAPDU command, boolean debug)
			throws CardException {
		// Send command via card channel
		if (debug) {
			System.out.println(" >> Sending command: " + Util.toHexString(command.getBytes()));
		}
		ResponseAPDU response = channel.transmit(command);
		int status = response.getSW();

		// Check response status (0x9000 means success)
		if (status == 0x9000) {
			if (debug) {
				System.out.println(" << Response: " + Util.toHexString(response.getData()));
			}
			return response.getData();
		} else if (status == 0x6700) {
			throw new CardException("Response status: 0x6700 (incorrect length)");
		} else if (status == 0x6900) {
			throw new CardException("Response status: 0x6900 (command not allowed)");
		} else if (status == 0x6A80) {
			throw new CardException("Response status: 0x6a80 (incorrect data)");
		} else if (status == 0x6A82) {
			throw new CardException("Response status: 0x6a82 (file not found)");
		}

		throw new CardException("Response status: 0x" + Integer.toHexString(status));
	}
}
