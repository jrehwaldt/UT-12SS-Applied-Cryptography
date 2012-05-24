package hw3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

/*
 * You do not have to change anything here.
 */

/**
 * <p>Estonian ID card tool.</p>
 * 
 * <p>Usage:</p>
 * 
 * <p>Loading default parameters:</p>
 * 
 * <pre>
 * CardChannel cardChannel = ...
 * EstEidHandler eid = new EstEidHandler(cardChannel);
 * eid.loadProperties();
 * </pre>
 * 
 * <p>Providing hard-coded PINs (bad idea):</p>
 *
 * <pre>
 * CardChannel cardChannel = ...
 * EstEidHandler eid = new EstEidHandler(cardChannel);
 * eid.setPin1("1234".getBytes()); // Needed mostly for decryption operations
 * eid.setPin1("12345".getBytes()); // Needed mostly for signing operations
 * </pre>
 */
public class EstEidHandler {
	private static byte[] personalDirId = new byte[] { (byte) 0xEE, (byte) 0xEE };
	private static byte[] personalDataFileId = new byte[] { (byte) 0x50, (byte) 0x44 };
	private static byte[] pinCounterFileId = new byte[] { (byte) 0x00, (byte) 0x16 };

	private boolean safeMode;
	private byte[] pin1;
	private byte[] pin2;
	private byte[] puk;
	private byte[] selectedFile;
	private CardChannel cardChannel;



	public EstEidHandler(CardChannel cardChannel) {
		this.cardChannel = cardChannel;
		this.pin1 = null;
		this.pin2 = null;
		this.puk = null;
		this.safeMode = true;
		this.selectedFile = null;
	}

	/**
	 * <p>Loads configuration parameters from default properties file.</p>
	 * 
	 * <p>Default properties file is {$USER_HOME}/.esteid.conf.</p>
	 * 
	 * {@see #loadProperties(String)}
	 */
	public EstEidHandler loadProperties() throws IOException {
		String filePath = System.getProperty("user.home")
				+ System.getProperty("file.separator")
				+ ".esteid.conf";
		return loadProperties(filePath);
	}

	/**
	 * <p>Loads configuration parameters from this properties file.</p>
	 * 
	 * <p>Configuration file format (every line is optional):</p>
	 * 
	 * <pre>
	 *   pin1 = 0000
	 *   pin2 = 00000
	 *   puk = 00000000
	 * </pre>
	 */
	public EstEidHandler loadProperties(String filePath) throws IOException {
		Properties properties = new Properties();
		properties.load(new FileInputStream(filePath));

		String pin1Str = properties.getProperty("pin1");
		if (pin1Str != null) {
			pin1 = pin1Str.getBytes();
		}

		String pin2Str = properties.getProperty("pin2");
		if (pin2Str != null) {
			pin2 = pin2Str.getBytes();
		}

		String pukStr = properties.getProperty("puk");
		if (pukStr != null) {
			puk = pukStr.getBytes();
		}

		return this;
	}

	/**
	 * Sets PIN1 code to use for cryptographic operations.
	 * 
	 * @param pin1 PIN1 as ASCII chars, example: {@code "1234".getBytes()}.
	 */
	public EstEidHandler setPin1(byte[] pin1) {
		this.pin1 = pin1;
		return this;
	}

	/**
	 * Sets PIN2 code to use for cryptographic operations.
	 * 
	 * @param pin2 PIN1 as ASCII chars, example: {@code "12345".getBytes()}.
	 */
	public EstEidHandler setPin2(byte[] pin2) {
		this.pin2 = pin2;
		return this;
	}

	public EstEidHandler setPuk(byte[] puk) {
		this.puk = puk;
		return this;
	}

	/**
	 * <p>Turns safe mode or on off. By default, safe mode is on.</p>
	 * 
	 * <p>If safe mode is enabled, no PIN operations will be allowed if PIN attempts counter
	 * value is < 3. This will prevent your -- possible faulty -- code from accidentally
	 * blocking the card. Disable safe mode only if you are <b>absolutely sure</b> you
	 * know what you are doing.</p>
	 * 
	 * <p>If any of the PINs gets blocked, you can use {@link #unblockPin(int)} method.</p>
	 * 
	 * <p>If PUK gets blocked, you may consider your card bricked.</p>
	 *  
	 * @param isEnabled {@code true} to enable safe mode, {@code false} to disable safe mode.
	 */
	public EstEidHandler setSafeMode(boolean isEnabled) {
		this.safeMode = isEnabled;
		return this;
	}



	/*
	 * Personal data file fields
	 */

	public Date getBirthDate() throws CardException {
		return readPersonalDataDate(6);
	}

	public String getBirthPlace() throws CardException {
		return readPersonalDataRecord(10);
	}

	public String getCitizenship() throws CardException {
		return readPersonalDataRecord(5);
	}

	public String getDocumentNumber() throws CardException {
		return readPersonalDataRecord(8);
	}

	public Date getDocumentValidFrom() throws CardException {
		return readPersonalDataDate(11);
	}

	public Date getDocumentValidUntil() throws CardException {
		return readPersonalDataDate(9);
	}

	public String getFirstName() throws CardException {
		return readPersonalDataRecord(2);
	}

	public String getGender() throws CardException {
		return readPersonalDataRecord(4);
	}

	public String getLastName() throws CardException {
		return readPersonalDataRecord(1);
	}

	public String getMiddleName() throws CardException {
		return readPersonalDataRecord(3);
	}

	public String[] getNotes() throws CardException {
		return new String[] {
				readPersonalDataRecord(13),
				readPersonalDataRecord(14),
				readPersonalDataRecord(15),
				readPersonalDataRecord(16)
		};
	}

	public String getPersonalCode() throws CardException {
		return readPersonalDataRecord(7);
	}

	public String getResidencePermitType() throws CardException {
		return readPersonalDataRecord(12);
	}



	/*
	 * Certificates
	 */

	public X509Certificate getAuthenticationCertificate() throws CardException {
		// File AA CE, client certificate -- max size 1536 bytes
		return readCertificate(new byte[] { (byte) 0xAA, (byte) 0xCE }, 1536); 
	}

	public X509Certificate getRootCertificate() throws CardException {
		// File CA CE, root certificate -- max size 1792 bytes
		return readCertificate(new byte[] { (byte) 0xCA, (byte) 0xCE }, 1792);
	}

	public X509Certificate getSigningCertificate() throws CardException {
		// File DD CE, client certificate -- max size 1536 bytes
		return readCertificate(new byte[] { (byte) 0xDD, (byte) 0xCE }, 1536);
	}



	/*
	 * PIN operations
	 */

	/**
	 * <p>Decrypts this ciphertext. Needs PIN1 to be set.</p>
	 * 
	 * <p>For demo purposes, can handle data chunks up to 128 bytes.</p>
	 * 
	 * <p><b>DANGER!</b> This will modify PIN1 counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.</p>
	 * 
	 * {@see #setPin1(byte[])}
	 */
	public byte[] decryptData(byte[] ciphertext) throws CardException {
		if (pin1 == null) {
			throw new IllegalStateException("PIN1 not set");
		}

		// Check if enough PIN1 attempts remaining
		if (safeMode) {
			int attemptsRemaining = getPinAttemptsRemaining(1);
			if (attemptsRemaining < 3) {
				throw new IllegalStateException(
						"Too few PIN1 attempts remaining: " + attemptsRemaining);	
			}
		}

		// Select personal dedicated file
		if (!Arrays.equals(selectedFile, personalDirId)) {
			selectMasterFile();
			selectDedicatedFile(personalDirId);
			selectedFile = personalDirId;
		}

		// Set security environment 6
		setSecurityEnvironment(6); // Decryption

		// Set up secuity environment: do not authenticate now
		SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0x22, 0x41, 0xA4, new byte[] { (byte) 0x83, 0x00 }));

		// Set up secuity environment: do not encrypt now
		SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0x22, 0x41, 0xB6, new byte[] { (byte) 0x83, 0x00 }));

		// Use authentication key
		SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0x22, 0x41, 0xB8, new byte[] {
						(byte) 0x83, 0x03, (byte) 0x80, 0x11, (byte) 0x00}));

		verifyPin(1); // PIN1

		// Ciphertext to be decrypted should be prepended by 0x00 byte:
		byte[] lvCiphertext = new byte[ciphertext.length + 1];
		lvCiphertext[0] = 0x00;
		System.arraycopy(ciphertext, 0, lvCiphertext, 1, ciphertext.length);

		// Decrypt ciphertext and return plaintext bytes
		return SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0x2A, 0x80, 0x86, lvCiphertext, 256));
	}

	/**
	 * <p>Returns PIN code attempts remaining.</p>
	 * 
	 * <p>By default, PIN attempts counter is set to 3. With every incorrect PIN attempts,
	 * counter is decremented by 1. Once the counter reaches 0, you cannot use PIN-related
	 * functionality until the card is unblocked.</p>
	 * 
	 * <p>There are two PIN codes used by Estonian ID cards.
	 * PIN1 is used mostly for decryption, and PIN2 is used mostly for signing.</p>
	 * 
	 * @param pinId either 1 for PIN1 or 2 for PIN2.
	 */
	public int getPinAttemptsRemaining(int pinId) throws CardException {
		if (pinId < 1 || pinId > 2) {
			throw new IllegalArgumentException("Invalid PIN ID: " + pinId + " -- should be 1 or 2");
		}

		if (!Arrays.equals(selectedFile, pinCounterFileId)) {
			selectMasterFile();
			selectElementaryFile(pinCounterFileId);
			selectedFile = pinCounterFileId;
		}

		return readRecord(pinId)[5];
	}

	public int getPukAttemptsRemaining() throws CardException {
		if (!Arrays.equals(selectedFile, pinCounterFileId)) {
			selectMasterFile();
			selectElementaryFile(pinCounterFileId);
			selectedFile = pinCounterFileId;
		}

		return readRecord(3)[5];
	}

	/**
	 * <p>Computes data digest and signs it. Needs PIN2 to be set.</p>
	 * 
	 * <p>For demo purposes, can handle data chunks up to 40 bytes.</p>
	 * 
	 * <p>Signature algorithm is {@code SHA1withRSA}.</p>
	 * 
	 * <p><b>DANGER!</b> This will modify PIN2 counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.</p>
	 * 
	 * {@see #setPin2(byte[])}
	 */
	public byte[] signData(byte[] data) throws CardException {
		return sign(data, false);
	}

	/**
	 * <p>Signs this message digest value. Needs PIN2 to be set.</p>
	 * 
	 * <p>Digest should be DER-encoded {@code MessageImprint}:</p>
	 * 
	 * <pre>
	 *   MessageImprint ::= SEQUENCE {
	 *     hashAlgorithm  AlgorithmIdentifier, -- SHA1
	 *     hashedMessage  OCTET STRING
	 *   }
	 * </pre>
	 * 
	 * <p>Signature algorithm is {@code SHA1withRSA}.</p>
	 * 
	 * <p><b>DANGER!</b> This will modify PIN2 counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.</p>
	 * 
	 * {@see #setPin2(byte[])}
	 */
	public byte[] signDigest(byte[] digest) throws CardException {
		return sign(digest, true);
	}

	/**
	 * <p>Unlocks the blocked PIN code. Needs PUK to be set.</p>
	 * 
	 * <p>Note that this only works if the particular PIN code is blocked.</p>
	 * 
	 * <p><b>DANGER!</b> This will modify PUK counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.</p>
	 * 
	 * @param pinId 1 for PIN1, 2 for PIN2.
	 * 
	 * {@see #setPuk(byte[])}
	 */
	public void unlockPin(int pinId) throws CardException {
		if (pinId < 1 || pinId > 2) {
			throw new IllegalArgumentException("Invalid PIN ID: " + pinId + " -- should be 1 or 2");
		}

		// Check if enough PUK attempts remaining
		if (safeMode) {
			int attemptsRemaining = getPukAttemptsRemaining();
			if (attemptsRemaining < 3) {
				throw new IllegalStateException(
						"Too few PUK attempts remaining: " + attemptsRemaining);	
			}
		}

		verifyPuk();
		SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0x2C, 0x03, pinId));
	}



	/*
	 * Direct Smart Card commands
	 */

	/**
	 * Reads data from selected file starting from this offset (max maxLength bytes).
	 */
	private byte[] readBinary(int offset, int maxLength) throws CardException, IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		while (offset < maxLength) {
			// Convert (int) offset to (byte[2]) offset
			int offsetH = offset >> 8;
			int offsetL = offset % 256;

			// Example:
			// int offset = 259 = 0x0103 = 0000-0001-0000-0011 (bin)
			//
			// We need byte offsetH = 0000-0001 (bin) and byte offsetL =
			// 0000-0011 (bin)
			//
			// offsetH = 0000-0001-0000-0011 (bin) >> 8 = 0000-0001 (bin) = 1
			// offsetL = 259 % 256 = 3 = 0000-0011 (bin)

			byte[] buffer = SmartCardUtil.runCommand(cardChannel,
					new CommandAPDU(0x00, 0xB0, offsetH, offsetL, 256));
			out.write(buffer);
			offset += buffer.length;
		}

		return out.toByteArray();
	}

	private byte[] readRecord(int recordId) throws CardException {
		return SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0xB2, recordId, 0x04, 256));
	}

	private byte[] selectDedicatedFile(byte[] fileId) throws CardException {
		selectedFile = fileId;
		return SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0xA4, 0x01, 0x0C, fileId));
	}

	private byte[] selectElementaryFile(byte[] fileId) throws CardException {
		selectedFile = fileId;
		return SmartCardUtil.runCommand(cardChannel,
				new CommandAPDU(0x00, 0xA4, 0x02, 0x0C, fileId));
	}

	private byte[] selectMasterFile() throws CardException {
		selectedFile = null;
		return SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0xA4, 0x00, 0x0C));
	}

	/**
	 * Sets security environment to use.
	 * 
	 * Environment IDs are:
	 *  1. PKI environment -- authentication with PIN codes
	 *  2. PKI environment with secured communication
	 *  3. Certificate upload environment -- generating new keypairs, uploading certificates
	 *  4. Authentication object management environment
	 *  5. Additional application environment
	 *  6, 7. Decryption environment
	 * 
	 * If in doubt, use environment #1.
	 */
	private void setSecurityEnvironment(int environmentId) throws CardException {
		SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0x22, 0xF3, environmentId));		
	}

	/**
	 * Verifies PIN code.
	 * 
	 * <b>DANGER!</b> This will modify PIN counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.
	 */
	private void verifyPin(int pinId) throws CardException {
		byte[] pinValue = null;
		if (pinId == 1) {
			pinValue = pin1;
		} else if (pinId == 2) {
			pinValue = pin2;
		} else {
			throw new IllegalArgumentException("Invalid PIN ID: " + pinId);
		}

		SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0x20, 0x00, pinId, pinValue));
	}

	/**
	 * Verifies PUK code.
	 * 
	 * <b>DANGER!</b> This will modify PUK counter on every failed attempt.
	 * Use <b>very</b> carefully -- you've been warned.
	 */
	private void verifyPuk() throws CardException {
		SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0x20, 0x00, 0x00, puk));
	}



	/*
	 * Helper methods
	 */

	private X509Certificate readCertificate(byte[] fileId, int maxLength) throws CardException {
		if (!Arrays.equals(selectedFile, fileId)) {
			selectMasterFile();
			selectDedicatedFile(personalDirId);
			selectElementaryFile(fileId);
			selectedFile = fileId;
		}

		byte[] certificateBytes = null;
		try {
			certificateBytes = readBinary(0, maxLength);
		} catch (IOException e) {
			throw new CardException(e.getMessage());
		}
		ByteArrayInputStream in = new ByteArrayInputStream(certificateBytes);

		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
		} catch (CertificateException e) {
			throw new CardException(e.getMessage());
		}
	}

	private Date readPersonalDataDate(int fieldId) throws CardException {
		try {
			return new SimpleDateFormat("dd.MM.yyyy").parse(readPersonalDataRecord(fieldId));
		} catch (ParseException e) {
			throw new CardException(e.getMessage());
		}		
	}

	/**
	 * Reads record from personal data elementary file, selects the file if needed.
	 * 
	 * Record IDs are:
	 *  1. Last name (28 bytes)
	 *  2. First name (15 bytes)
	 *  3. Middle name (15 bytes)
	 *  4. Gender (1 byte)
	 *  5. Citizenship (3 bytes) -- 3-letter country code, uppercase
	 *  6. Date of birth (10 bytes) -- DD.MM.YYYY
	 *  7. Personal code (11 bytes)
	 *  8. Document number (8 bytes)
	 *  9. Last day of document validity period (10 bytes) -- DD.MM.YYYY
	 *  10. Place of birth (35 bytes)
	 *  11. Document issue date (10 bytes) -- DD.MM.YYYY
	 *  12. Type of residence permit (50 bytes)
	 *  13. Notes 1 (50 bytes)
	 *  14. Notes 2 (50 bytes)
	 *  15. Notes 3 (50 bytes)
	 *  16. Notes 4 (50 bytes)
	 * 
	 * All fields are encoded in ANSI-1252.
	 */
	private String readPersonalDataRecord(int recordId) throws CardException {
		if (!Arrays.equals(selectedFile, personalDataFileId)) {
			selectMasterFile();
			selectDedicatedFile(personalDirId);
			selectElementaryFile(personalDataFileId);
			selectedFile = personalDataFileId;
		}

		byte[] responseData = readRecord(recordId);

		return new String(responseData);
	}

	private byte[] sign(byte[] data, boolean dataIsDigest) throws CardException {
		if (pin2 == null) {
			throw new IllegalStateException("PIN2 not set");
		}

		// Check if enough PIN2 attempts remaining
		if (safeMode) {
			int attemptsRemaining = getPinAttemptsRemaining(2);
			if (attemptsRemaining < 3) {
				throw new IllegalStateException(
						"Too few PIN2 attempts remaining: " + attemptsRemaining);	
			}
		}

		// Select personal dedicated file
		if (!Arrays.equals(selectedFile, personalDirId)) {
			selectMasterFile();
			selectDedicatedFile(personalDirId);
			selectedFile = personalDirId;
		}

		// Set security environment 1 and verify PIN
		setSecurityEnvironment(1); // PKI
		verifyPin(2); // PIN2

		CommandAPDU signCommand = null;
		if (dataIsDigest) {
			// Digest provided -- send to card for signing, no extra magic is needed
			signCommand = new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, data, 256);
		} else {
			// Data to be sent to digest calculator should be in TLV format:
			// [0x80] [data-length] [[[data]]]
			byte[] tlvData = new byte[data.length + 2];
			tlvData[0] = (byte) 0x80; // Type
			tlvData[1] = (byte) data.length; // Length
			System.arraycopy(data, 0, tlvData, 2, data.length);

			// Compute message digest -- result is temporarily stored on card
			SmartCardUtil.runCommand(cardChannel, new CommandAPDU(0x00, 0x2A, 0x90, 0xA0, tlvData));

			// Sign digest and return signature value
			// Note that data is empty here -- using previously computed digest
			signCommand = new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, 256);
		}

		return SmartCardUtil.runCommand(cardChannel, signCommand);
	}
}
