import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.DataOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Key;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.UnrecoverableEntryException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.util.Base64;

public class Authenticator {
	private SSLSocket socket;
	private SSLContext ctx;
	final static private byte CERTIFICATE_REQUEST = 0;
	final static private byte CERTIFICATE_RESPONSE = 1;
	final static private byte SIGNATURE_REQUEST = 2;
	final static private byte SIGNATURE_RESPONSE = 3;
	private char[] pass = "nopass".toCharArray();
	private char[] ksPass = "nopass".toCharArray();

	public Authenticator() {
		this.socket = null;
		try{
		    ctx = SSLContext.getInstance("TLS");
		    ctx.init(null, new TrustManager[] { new ClientAuthTrustManager() }, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
		PrivateKey key = readKey();
		X509Certificate[] certificates = readCertificates();
		try {
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(null);
			ks.setKeyEntry("hax0r.online", key, pass, certificates);
			FileOutputStream fos = new FileOutputStream("keystore");
			ks.store(fos, ksPass);
		}
		catch (KeyStoreException e) {
			e.printStackTrace();
		}
		catch (CertificateException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	public boolean connect(String addr, int port) {
		try {
			this.socket = (SSLSocket) ctx.getSocketFactory().createSocket(addr, port);
		}
		catch (UnknownHostException e) {
		}
		catch (IOException e) {
		}
		if (this.socket == null) {
			return false;
		}
		return true;
	}

	public void serve() {
		try {
			InputStream is = this.socket.getInputStream();
			DataInputStream dis = new DataInputStream(is);
			OutputStream os = this.socket.getOutputStream();
			DataOutputStream dos = new DataOutputStream(os);
            String hostname = "";
			while (this.socket.isConnected()) {
                System.out.println("Reading a byte");
                byte type = dis.readByte();
                if(type == 0) {
                    hostname = readCertificateRequest(dis);
                    System.out.println("Hostname is " + hostname);
                    byte[] certificate = getCertificateBytes(hostname);
                    sendCertificateResponse(dos, certificate);
                }else if(type == 2) {
                    byte[] handshakeData = readSignatureRequest(dis);
                    byte[] signedData = signHandshakeData(hostname, 0, handshakeData);
                    sendSignatureResponse(dos, signedData);
                }else{
                    System.out.println("READ AN INCORRECT BYTE");
                }
			}
		}
		catch (IOException e) {
			e.printStackTrace();
			return;
		}
		return;
		
	}

	public void disconnect() {
		try {
			socket.close();
		}
		catch (IOException e) {
		}
		return;
	}

	private String readCertificateRequest(DataInputStream dis) throws IOException {
		System.out.println("Reading an int");
		int data_length = dis.readInt();
		System.out.println("Data length is " + data_length);
		byte[] data = new byte[data_length];
		dis.readFully(data);
		return new String(data);
	}
	
	private byte[] readSignatureRequest(DataInputStream dis) throws IOException {
		System.out.println("Reading an int");
		int data_length = dis.readInt();
		System.out.println("Reading an int");
		int sigalg_id = dis.readInt();
		data_length -= 4;
		System.out.println("Data length is " + data_length);
		byte[] data = new byte[data_length];
		dis.readFully(data);
		return data;
	}

	private void sendCertificateResponse(DataOutputStream dos, byte[] certificate) throws IOException {
		dos.writeByte(CERTIFICATE_RESPONSE);
		dos.writeInt(certificate.length);
		System.out.println("Sending back " + certificate.length + " bytes");
		dos.write(certificate, 0, certificate.length);
		return;
	}
	
	private void sendSignatureResponse(DataOutputStream dos, byte[] signedData) throws IOException {
		dos.writeByte(SIGNATURE_RESPONSE);
		dos.writeInt(signedData.length);
		System.out.println("Sending back " + signedData.length + " bytes");
		dos.write(signedData, 0, signedData.length);
		return;
	}

	private X509Certificate[] readCertificates() {
		try {
			File file = new File("../openssl_mod_tests/client_pub.pem");
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[(int) file.length()];
			fis.read(data);
			fis.close();

			CertificateFactory cf = CertificateFactory.getInstance("X509");
			ByteArrayInputStream in = new ByteArrayInputStream(data);
			X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
			X509Certificate[] certs = {cert};
			return certs;
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (CertificateException e) {
			e.printStackTrace();
		}
		return null;
	}

	private byte[] getCertificateBytes(String hostname) {
		/* Really this should import the cert from the keystore
		 * and then convert it to a PEM byte array. We're just
		 * reading from the file directly for simplicity */
		try {
			File file = new File("../openssl_mod_tests/client_pub.pem");
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[(int) file.length()];
			fis.read(data);
			fis.close();
			return data;
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private PrivateKey readKey() {
		try {
			String keyString;
			byte[] keyData;
			File file = new File("../openssl_mod_tests/client_key.key");
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[(int) file.length()];
			fis.read(data);
			fis.close();

			keyString = new String(data);
			keyString = keyString.replaceAll("\r", "");
			keyString = keyString.replaceAll("\n", "");
			keyString = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
			keyString = keyString.replace("-----END PRIVATE KEY-----", "");
			keyData = Base64.getDecoder().decode(keyString);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey key = kf.generatePrivate(keySpec);
			return key;
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	private byte[] signHandshakeData(String hostname, int algID, byte[] handshakeData) {
		try {
			Signature s = Signature.getInstance("SHA512withRSA");
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			FileInputStream fis = new FileInputStream("keystore");
			ks.load(fis, ksPass);
			ProtectionParameter protParam = new KeyStore.PasswordProtection(pass);
			System.out.println("Getting key using hostname: " + hostname);
			KeyStore.Entry entry = ks.getEntry(hostname, protParam);
			if (!(entry instanceof PrivateKeyEntry)) {
				System.out.println("Unable to fetch keystore entry");
				return null;
			}
			s.initSign(((PrivateKeyEntry) entry).getPrivateKey());
			s.update(handshakeData);
			byte[] signature = s.sign();
			return signature;
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (KeyStoreException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (CertificateException e) {
			e.printStackTrace();
		}
		catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		catch (UnrecoverableEntryException e) {
			e.printStackTrace();
		}
		catch (SignatureException e) {
			e.printStackTrace();
		}
		catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	class ClientAuthTrustManager implements X509TrustManager {
		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			throw new CertificateException(); // we are not a server
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			//automatically connect without verification
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}

	}
}
