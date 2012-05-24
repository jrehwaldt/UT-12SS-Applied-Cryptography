package lab18;

import java.io.ByteArrayInputStream;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import common.SmartCardUtil;
import common.Util;

/*
 * This class demonstrates how to start access smart cards in Java.
 * 
 * `javax.smartcardio` package documentation:
 * http://docs.oracle.com/javase/6/docs/jre/api/security/smartcardio/spec/javax/smartcardio/package-summary.html
 * 
 * All APDU commands are implemented based on this manual:
 * http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_6_basic_interindustry_commands.aspx
 */
@SuppressWarnings("restriction")
public class SmartCardDemo {
	public static void main(String[] args) throws CardException {
		Card card = SmartCardUtil.connectCard();
		System.out.println("Card connected: " + card);

		// Get card answer to reset
		String atrHexStr = Util.toHexString(card.getATR().getBytes());
		System.out.println("Card ATR: " + atrHexStr);
		System.out.println("More info: http://smartcard-atr.appspot.com/parse?ATR=" + atrHexStr);


		if ("3bea00008131fe45436f6d624f5320494900fe".equals(atrHexStr)) {
			printEmvData(card);
		} else {
			printEstEidData(card);
		}
	}



	/**
	 * Prints some meta data from EMV card (Visa, MasterCard, etc.)
	 */
	private static String printEmvData(Card card) throws CardException {
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

		// Read PSE application data to get application ID
		//
		// Application ID is the file name where the application can be found.
		// We will then extract card holder name from this application.
		//
		// Should work on MasterCard but may fail on Visa cards
		System.out.println("Reading PSE application ID...");

		// Select PSE file
		byte[] pseFileName = "1PAY.SYS.DDF01".getBytes();
		SmartCardUtil.runCommand(
				cardChannel, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, pseFileName, 256));

		// Read PSE record from underlying elementary file
		response = SmartCardUtil.runCommand(
				cardChannel, new CommandAPDU(0x00, 0xB2, 0x01, 0x0C, 256));

		/*
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
		 * 
		 * All magic numbers taken from EMV specification.
		 */

		byte[] applicationId = null;
		in = new ByteArrayInputStream(response, 4, response[3]); // ##0..2 skipped -- see above
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

		// Select application file
		System.out.println("Reading PSE application record...");
		SmartCardUtil.runCommand(
				cardChannel, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, applicationId, 256));

		// Read application record from underlying elementary file
		response = SmartCardUtil.runCommand(
				cardChannel, new CommandAPDU(0x00, 0xB2, 0x01, 0x0C, 256));

		String cardHolderNameStr = null;
		in = new ByteArrayInputStream(response, 2, response[1]); // #0 -- tag -- is skipped
		while (in.available() > 0) {
			int entryTag = in.read(); // First entry byte should be entry tag
			if (entryTag == 0x5F || entryTag == 0x9F) { // .. 5F means that tag is actually two-bytes long
				entryTag = (entryTag << 8) + in.read();
			}
			int entryLength = in.read(); // Next byte should be entry length

			if (entryTag == 0x57) { // Data equivalent to that on magnet track 2
				byte[] track2Data = new byte[entryLength];
				in.read(track2Data, 0, entryLength);
				System.out.println(" * Track 2 data: " + Util.toHexString(track2Data));
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



	/**
	 * Prints personal data from Estonian ID card
	 */
	private static void printEstEidData(Card card) throws CardException {
		/*
		 * Estonian ID card file system (some files skipped):
		 * 
		 * Master file
		 * |
		 * +--0016 -- elementary file, contains PIN1 and PIN2 counter values
		 * |
		 * +--EEEE -- dedicated file
		 *    |
		 *    +--5044 -- elementary file, contains personal data (16 fields)
		 * 
		 * PIN counter value format:
		 * 
		 * [80] [01] [N] [90] [01] [M] [83] [02] [XX]
		 * whereas N is maximum allowed number of attempts and M is number of attempts remaining.
		 * 
		 * Command to select master file:
		 * CLA=0x00 INS=0xA4 P1=0x00 P2=0x0C
		 * 
		 * Command to select dedicated file:
		 * CLA=0x00 INS=0xA4 P1=0x01 P2=0x0C
		 *
		 * Command to select elementary file:
		 * CLA=0x00 INS=0xA4 P1=0x02 P2=0x0C
		 *
		 * Command to read record:
		 * CLA=0x00 INS=0xB2 P1=<record-number> P2=0x04
		 * 
		 * TODO: Print (some) personal data and PIN counter values.
		 */
	}
}
