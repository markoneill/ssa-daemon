public class TestAuth {
	public static void main(String[] args) {
		Authenticator auth = new Authenticator();
		if (!auth.connect("localhost", 6666)) {
			System.out.println("Could not connect to host");
			return;
		}
		auth.serve();
		//auth.disconnect();
	}
}
