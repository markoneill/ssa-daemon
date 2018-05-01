import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.DataOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.Socket;
import java.net.UnknownHostException;

public class Authenticator {
	private Socket socket;

	public Authenticator() {
		this.socket = null;
	}

	public boolean connect(String addr, int port) {
		try {
			this.socket = new Socket(addr, port);
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
			DataInputStream in = new DataInputStream(is);
			OutputStream os = this.socket.getOutputStream();
			DataOutputStream dos = new DataOutputStream(os);
			while (this.socket.isConnected()) {
				System.out.println("Reading a byte");
				byte type = in.readByte();
				System.out.println("Reading an int");
				int data_length = in.readInt();
				System.out.println("Data length is " + data_length);
				byte[] data = new byte[data_length];
				if (in.read(data, 0, data_length) != data_length) {
					System.out.println("Couldn't read everything");
				}
				System.out.println(new String(data));
				byte[] certificate = readCertificate();
				dos.writeByte(1);
				dos.writeInt(certificate.length);
				System.out.println("Sending back " + certificate.length + " bytes");
				dos.write(certificate, 0, certificate.length);
			}
		}
		catch (IOException e) {
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

	private byte[] readCertificate() {
		try {
			File file = new File("../openssl_mod_tests/client_pub.pem");
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[(int) file.length()];
			fis.read(data);
			fis.close();
			return data;
		}
		catch (IOException e) {
		}
		return null;
	}
}
