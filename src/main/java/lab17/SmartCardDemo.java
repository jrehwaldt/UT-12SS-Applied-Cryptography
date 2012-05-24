package lab17;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import common.Util;

/*
 * This class demonstrates how to start access smart cards in Java.
 * 
 * `javax.smartcardio` package documentation:
 * http://docs.oracle.com/javase/6/docs/jre/api/security/smartcardio/spec/javax/smartcardio/package-summary.html
 */
public class SmartCardDemo {
	
	private static CommandAPDU SELECT_MASTER_FILE = new CommandAPDU(new byte[]{0x00, (byte)0xA4, 0x00, 0x0C});  
	private static CommandAPDU SELECT_FILE_EEEE = new CommandAPDU(new byte[]{0x00, (byte)0xA4, 0x01, 0x0C, 0x02, (byte)0xEE, (byte)0xEE});  
	private static CommandAPDU SELECT_FILE_5044 = new CommandAPDU(new byte[]{0x00, (byte)0xA4, 0x02, 0x04, 0x02, (byte)0x50, (byte)0x44});

	@SuppressWarnings("unused")
	public static void main(String[] args)
			throws CardException {
		Card card = connectCard();

		/*
		 * First message you typically get from card is answer-to-reset (ATR).
		 * 
		 * ATR contains card communication parameters and also some information
		 * about the card type and state.
		 * 
		 * See also: http://en.wikipedia.org/wiki/Answer_to_reset
		 * 
		 * Part of ATR message is called 'historical bytes'. We will use this
		 * section to find out the card type.
		 * 
		 * Refer to this list to decode ATR:
		 * http://ludovic.rousseau.free.fr/softwares
		 * /pcsc-tools/smartcard_list.txt
		 * 
		 * ... or you can use this online parser:
		 * http://smartcard-atr.appspot.com
		 */

		// TODOdone: Get card's answer-to-reset
		ATR atr = card.getATR();
		
		// TODOdone: Print both ATR and historical bytes from as hex strings
		
		// 3B FE 18 00 00 80 31 FE 45 45 73 74 45 49 44 20 76 65 72 20 31 2E 30 A8
		// Estonian Identity Card (EstEID 3.0 "JavaCard" cold)
		System.out.println(String.format("ATR: %s", Util.toHexString(atr.getBytes())));
		System.out.println(String.format("Historical Bytes: %S", Util.toHexString(atr.getHistoricalBytes())));
		System.out.println(String.format("Historical Text: %s", new String(atr.getHistoricalBytes())));
		// Q: Do historical bytes contain any human-readable information?
			// EstEID: EstEID ver 1.0
			// others may not
		
		if ("EstEID ver 1.0".equals(new String(atr.getHistoricalBytes()))) {
			
			//
			// http://id.ee/?id=10457
			//
			CardChannel channel = card.getBasicChannel();
			byte[] fileMaster = runCommand(channel, SELECT_MASTER_FILE);
			byte[] fileEeee = runCommand(channel, SELECT_FILE_EEEE);
			byte[] file5044 = runCommand(channel, SELECT_FILE_5044);
			
			for (byte i = 1; i <= 16; i++) {
				String result = bytesToString(runCommand(
						channel,
						new CommandAPDU(new byte[] { 0x00, (byte)0xB2, i, 0x04, 0x00 } )));
				System.out.println(result);
			}
		} else {
			// Get card holder name from EMV card
			String cardHolderName = getEmvCardHolderName(card);
			System.out.println("Card holder: " + cardHolderName);
		}
	}
	
	
	private static String ENCODING = "windows-1252";

	public static String bytesToString(byte[] data) {
		try {
			return new String(data, ENCODING);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("Encoding " + ENCODING + " not supported");
		}
	}

	/**
	 * Establishes the connection with the card (if present) in the first
	 * available terminal.
	 */
	private static Card connectCard()
			throws CardException {
		// Get list of available card terminals (readers)
		List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
		System.out.println(terminals.size() + " terminal(s) found");

		// Get the first available terminal
		CardTerminal terminal = terminals.get(0);
		System.out.println(" * Using terminal " + terminal.getName());

		// Check if card is present, exit if not
		if (!terminal.isCardPresent()) {
			System.err.println("Error: No card in reader");
			System.exit(-1);
		}

		/*
		 * There are two data transmission protocols to use when talking to
		 * smart cards: - 'T=0' is character-oriented, it is slower but uses
		 * less card memory. - 'T=1' is block-oriented, it is faster but uses
		 * more card memory.
		 * 
		 * You may also find references to 'T=CL' protocol. 'CL' here stands for
		 * contact-less.
		 */

		// Connect to card, let the underlying driver choose the protocol
		Card card = terminal.connect("*");
		System.out.println("Card connected: " + card);

		// Q: What protocols can your card run? How can you check that?
			// Only T=1 is supported on new EstEID
		
		return card;
	}

	/**
	 * Runs command on this card channel.
	 * 
	 * Be *very* careful with running commands!
	 * 
	 * Double-check what you are running, in order not to brick the card
	 * accidentally.
	 */
	private static byte[] runCommand(CardChannel channel, CommandAPDU command)
			throws CardException {
		/*
		 * Commands and responses are both known as application protocol data
		 * units (APDUs).
		 * 
		 * Command APDU consists of 4-byte header and 0..255 bytes of data.
		 * 
		 * Response APDU contains 0..256 bytes of response data and 2-byte
		 * status word.
		 * 
		 * See also:
		 * http://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
		 * 
		 * You don't have to do all the magic with byte arrays manually. There
		 * are handy types to use: - `javax.smartcardio.CommandAPDU` -
		 * `javax.smartcardio.responseAPDU`.
		 */

		// Send command via card channel
		System.out.println(" >> Sending command: "
				+ Util.toHexString(command.getBytes()));
		ResponseAPDU response = channel.transmit(command);

		/*
		 * Check this list to decode response status codes:
		 * http://www.wrankl.de/SCTables/SCTables.html#SCRC
		 */

		// Check response status (0x9000 means success)
		if (response.getSW() != 0x9000) {
			System.err.println("Error: Response status "
					+ Integer.toHexString(response.getSW()));
			System.exit(-1);
		}

		// Dump and return response contents
		System.out.println(" << Response: "
				+ Util.toHexString(response.getData()));

		return response.getData();
	}

	/**
	 * Reads card owner name from EMV card (Visa, MasterCard, etc.)
	 */
	private static String getEmvCardHolderName(Card card)
			throws CardException {
		/*
		 * EMV specifications can be found here (Book 1):
		 * http://www.emvco.com/specifications.aspx?id=155
		 * 
		 * Section 12.3.2 explains how to use PSE (Payment System Environment) record.
		 * 
		 * Section 11.3.4 explains how to decode protocol responses.
		 */

		// Open card channels to run commands on
		CardChannel cardChannel = card.getBasicChannel();

		byte[] response = null;
		ByteArrayInputStream in = null;

		System.out.println("Running EMV session...");

		// Select payment system environment (PSE) data record
		// Should work on MasterCard but may fail on Visa cards
		byte[] cmd = "1PAY.SYS.DDF01".getBytes();

		System.out.println("Selecting PSE...");
		response = runCommand(cardChannel, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, cmd, 256));

		/*
		 * Here we have run the 'select-file' command on card,
		 * as defined in ISO 7816-4 standard.
		 * 
		 * Command header consists of 4 bytes:
		 *  - 0x00 is command class (CLA), '0' means 'standard command';
		 *  - 0xA4 is command itself (INS), 'A4' means 'select file';
		 *  - 0X04 is first parameter (P1), '4' means 'file is directory'
		 *  - 0x00 is second parameter (P2), '0' means 'get the first record'
		 * 
		 * Then, data bytes contain the record name we are selecting: '1PAY.SYS.DDF01'.
		 * 
		 * Finally, 256 is maximum expected response length, in bytes.
		 * 
		 * See also:
		 * http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx#chap6_11
		 */

		// TODO Q: what happens if you try to run the command without specifying
		// the expected response length, like:
		// `new CommandAPDU(0x00, 0xA4, 0x04, 0x00, cmd)`?

		// Read PSE application data to get application ID
		//
		// Application ID is the file name where the application can be found.
		// We will then extract card holder name from this application.
		System.out.println("Reading PSE application data...");
		response = runCommand(cardChannel, new CommandAPDU(0x00, 0xB2, 0x01, 0x0C, 256));

		/*
		 * Here we have run the 'read-record' command.
		 * 
		 * INS=0xB2 means 'read record from selected file'.
		 * P1=0x01 means 'read record #1'
		 * p2=0x0C means 'read one record with # specified in P1'
		 * 
		 * Response will contain application data in the format
		 * defined in EMV specification Book 1 section 12.2.3:
		 * 
		 *     0:[70] 1:[data-length] 2..n:[[[data]]]
		 * 
		 * whereas [[[data]]] consists of several templates:
		 * 
		 *     2:[61] 3:[template-length] 4..m:[[[template]]]
		 * 
		 * whereas [[[template]]] has the following format:
		 * 
		 *     4:[tag] 5:[length] 6..k:[[[value]]]
		 * 
		 * and [value] after proper [tag] contains application ID we need.
		 * 
		 * One template can contain multiple TLV-s.
		 * 
		 * Or the same in in ASN.1:
		 * 
		 * Response ::= SEQUENCE {
		 *     dataTag ::= INTEGER { 0x70 },
		 *     dataLength ::= INTEGER { 1..0xFF },
		 *     data ::= SEQUENCE 1..N {
		 *         templateTag ::= INTEGER { 0x61 },
		 *         templateLength ::= INTEGER { 1..0xFF },
		 *         template ::= SEQUENCE 1..N {
		 *             entryTag ::= INTEGER { 0x4F | 0x50 | 0x73 | 0x87 | 0x9D },
		 *             entryLength ::= INTEGER { 1..0xFF },
		 *             entryValue ::= OCTET STRING -- <-- we need this with entryTag=0x4F
		 *         }
		 *     }
		 * }
		 */

		byte[] applicationId = null;
		in = new ByteArrayInputStream(response, 4, response[3]);
		while (in.available() > 0) {
			int entryTag = in.read(); // First entry byte should be entry tag
			if (entryTag == 0x9F) { // .. 9F means that tag is actually two-bytes long
				entryTag = (entryTag << 8) + in.read();
			}
			int entryLength = in.read(); // Next byte should be entry length

			if (entryTag == 0x4F) { // Application ID
				applicationId = new byte[entryLength];
				in.read(applicationId, 0, entryLength);
			} else if (entryTag == 0x50) { // Application label ('MASTERCARD', 'VISACREDIT', etc.)
				byte[] applicationLabel = new byte[entryLength];
				in.read(applicationLabel, 0, entryLength);
				System.out.println(" * Application label: " + new String(applicationLabel));
			} else if (entryTag == 0x9F12) { // Application name -- similar to label
				byte[] applicationName = new byte[entryLength];
				in.read(applicationName, 0, entryLength);
				System.out.println(" * Application name: " + new String(applicationName));
			} else { // Unknown entry -- just skipping
				in.skip(entryLength);
			}
		}

		// Select application to read the PSE record
		System.out.println("Selecting PSE application...");
		// TODO: implement

		// Hints:
		//  - Use the same 'select-file' command header as above
		//  - File name here is the application ID you've extracted before

		// Read PSE record to get card owner name
		System.out.println("Reading PSE record...");
		//TODO: implement

		// Hints:
		//  - Use the same 'read-record' command as above

		String cardHolderNameStr = null;
		in = new ByteArrayInputStream(response, 2, response[1]);
		while (in.available() > 0) {
			int entryTag = in.read(); // First entry byte should be entry tag
			if (entryTag == 0x5F || entryTag == 0x9F) { // .. 5F means that tag is actually two-bytes long
				entryTag = (entryTag << 8) + in.read();
			}
			int entryLength = in.read(); // Next byte should be entry length

			if (entryTag == 0x57) { // Data equivalent to that on magnet track 2
				byte[] track2Data = new byte[entryLength];
				in.read(track2Data, 0, entryLength);
				System.out.println(Util.toHexString(track2Data));
				// TODO Q: What can you read from this data?
			} else if (entryTag == 0x5F20) { // Card holder name
				byte[] cardHolderName = new byte[entryLength];
				in.read(cardHolderName, 0, entryLength);
				cardHolderNameStr = new String(cardHolderName);
				System.out.println(" * Card holder: " + cardHolderNameStr);
			} else { // Unknown entry -- just skipping
				in.skip(entryLength);
			}
		}

		return cardHolderNameStr;
	}

	/*
	 * Don't miss:
	 * 
	 * Nice tutorial about achieving the same on a bit more lower level:
	 * http://blog.saush.com/2006/09/08/getting-information-from-an-emv-chip-card/
	 */
}
