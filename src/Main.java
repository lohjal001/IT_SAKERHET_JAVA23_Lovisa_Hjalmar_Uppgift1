import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.HashMap;
import java.util.Scanner;

class main {
    private static final int PORT = 8080;
    private static final String HOST = "localhost";
    private static final HashMap<String, String> credentials = new HashMap<>();

    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);
        Socket socket = new Socket(HOST, PORT);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        // Ta in användarinmatning
        System.out.println("1. Register");

        System.out.println("2. Log in");

        System.out.println("3. Exit");

        System.out.println("Choose an alternative: ");
        String choice = scanner.nextLine();

        // Skapa ett UserRegistration-objekt och spara användarinformationen
        UsersHandling userRegistration = new UsersHandling();

        if (choice.equals("1")) {
            addUser();
        } if (choice.equals("2")) {
            System.out.print("Enter email: ");
            String email = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            UsersHandling userLogIn = new UsersHandling();
            boolean loginSuccessful = userLogIn.logIn(email, password);
            if (loginSuccessful) {
                System.out.println("You are logged in!");

                System.out.println("1. Delete my user info,");
                System.out.println("2. Go back to main menu,");
                String choice2 = scanner.nextLine();
                if (choice2.equals("1")) {
                    System.out.print("Enter your password to confirm deletion: ");
                    password = scanner.nextLine();
                    String hashedPassword = userLogIn.hashPassword(password);
                    UsersHandling userDeleteInfo = new UsersHandling();
                    userDeleteInfo.deleteUser(email, hashedPassword);
                }else if (choice2.equals("2")) {
                    System.exit(0);
                }
            } else {
                System.out.println("Login failed.");
            }
        }else if (choice.equals("3")) {
            System.exit(0);
        }
    }

    private static void addUser() {
        Scanner scanner = new Scanner(System.in);

        // Ta in användarinmatning
        System.out.print("Name: ");
        String name = scanner.nextLine();

        System.out.print("Email: ");
        String email = scanner.nextLine();

        System.out.print("Password: ");
        String password = scanner.nextLine();

        System.out.print("Adress: ");
        String adress = scanner.nextLine();

        // Skapa ett UserRegistration-objekt och spara användarinformationen
        UsersHandling userRegistration = new UsersHandling();
        userRegistration.saveToFile(name, password, email, adress);
    }
}



