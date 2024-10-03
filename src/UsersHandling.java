import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Paths;

public class UsersHandling {

    private static final String BASE_DIRECTORY = Paths.get("").toAbsolutePath().toString() + "/src/Files";

    // Metod för att hasha lösenord med SHA-256
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Kontrollera om filen ligger inom den tillåtna katalogen
    private File getSecureFile(String fileName) throws IOException {
        File file = new File(BASE_DIRECTORY, fileName);
        String canonicalBase = new File(BASE_DIRECTORY).getCanonicalPath();
        String canonicalFile = file.getCanonicalPath();

        // Kontrollera att filen ligger inom den tillåtna katalogen
        if (!canonicalFile.startsWith(canonicalBase)) {
            throw new SecurityException("Otillåten filåtkomst.");
        }
        return file;
    }

    // Metod för att spara användardata till en säker fil
    public void saveToFile(String name, String password, String email, String adress) {
        String hashedPassword = hashPassword(password);  // Hasha lösenordet
        try {
            // Använd säker filåtkomst
            File file = getSecureFile("users.txt");
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file, true))) {
                writer.write("Email: " + email);
                writer.newLine();
                writer.write("Hashed password: " + hashedPassword);
                writer.newLine();
                writer.write("Name: " + name);
                writer.newLine();
                writer.write("Adress: " + adress);
                writer.newLine();
                writer.write("----------------------------");
                writer.newLine();
                System.out.println("Användardata har sparats.");
            }
        } catch (IOException | SecurityException e) {
            e.printStackTrace();
        }
    }

    public boolean logIn(String email, String password) {
        String hashedPassword = hashPassword(password);
        System.out.println("Attempting to log in with email: " + email + " and hashed password: " + hashedPassword);

        try {
            // Använd säker filåtkomst
            File file = getSecureFile("users.txt");
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                String storedEmail = null;
                String storedPassword = null;
                StringBuilder userInfo = new StringBuilder();

                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("Email: ")) {
                        storedEmail = line.split("Email: ")[1].trim();
                    }
                    if (line.startsWith("Hashed password: ")) {
                        storedPassword = line.split("Hashed password: ")[1].trim();
                    }

                    userInfo.append(line).append("\n");

                    if (line.equals("----------------------------")) {
                        // Checks the email and password id the same
                        if (storedEmail != null && storedEmail.equals(email) && storedPassword != null && storedPassword.equals(hashedPassword)) {
                            System.out.println("Login successful. User information:");
                            System.out.println(userInfo.toString());  // Display user info
                            return true;
                        }

                        storedEmail = null;
                        storedPassword = null;
                        userInfo.setLength(0);  // Clear the StringBuilder
                    }
                }
            }
        } catch (IOException | SecurityException e) {
            System.out.println("Error: " + e.getMessage());
        }
        System.out.println("Login failed.");
        return false;
    }

    public void deleteUser(String email, String hashedPassword) {
        try {
            File file = getSecureFile("users.txt");
            File tempFile = new File(file.getAbsolutePath() + ".tmp");

            try (BufferedReader reader = new BufferedReader(new FileReader(file));
                 BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
                String line;
                boolean userFound = false;

                while ((line = reader.readLine()) != null) {
                    // Check if it contains the email
                    if (line.startsWith("Email: ")) {
                        String storedEmail = line.split("Email: ")[1].trim();
                        if (storedEmail.equals(email)) {
                            line = reader.readLine(); // Read the hashed password line
                            String storedPassword = line.split("Hashed password: ")[1].trim();

                            if (storedPassword.equals(hashedPassword)) {
                                userFound = true;
                                while ((line = reader.readLine()) != null && !line.equals("----------------------------")) {
                                }
                                continue;
                            }
                        }
                    }
                    writer.write(line);
                    writer.newLine();
                }

                if (userFound) {
                    System.out.println("User account deleted successfully.");
                } else {
                    System.out.println("User account not found or password did not match.");
                }
            }

            // Delete the original file and rename the temp file
            if (!file.delete()) {
                System.out.println("Could not delete the original file.");
            } else {
                if (!tempFile.renameTo(file)) {
                    System.out.println("Could not rename temp file.");
                }
            }

        } catch (IOException | SecurityException e) {
            System.out.println("Error while deleting user: " + e.getMessage());
        }
    }


}


