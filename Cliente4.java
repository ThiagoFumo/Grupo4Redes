import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLOutput;
import java.util.HashMap;
import java.util.Scanner;

public class Cliente4 {
    private static final String DIRECCION_IP_SERVIDOR = "127.0.0.1";
    private static final int PUERTO_SERVIDOR = 12345;
    private static Rsa rsa = new Rsa();

    private static HashMap<String, PublicKey> clavesUsuarios = new HashMap<>();


    public static void enviarMensaje(String mensaje, Socket socket) {
        try {
            Aes aes = new Aes();
            SecretKeySpec clave = aes.getKeyFromKeyGenerator("AES", 256);
            String claveString = aes.secretKeyToBase64(clave);
            PublicKey clavePublicaDestinatorio;
            String claveSimetrica;
            String firma;
            String msjClavePublica;
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
            if (mensaje.startsWith("@")) {
                String[] partes = mensaje.split(" ", 2);
                if (partes.length > 1) {
                    String destinatario = partes[0].substring(1);
                    String msj = partes[1];
                    escritor.println(destinatario);
                    clavePublicaDestinatorio = rsa.stringToPublic(lector.readLine());
                    claveSimetrica = rsa.encriptador(claveString, clavePublicaDestinatorio);
                    String msjHasheado = rsa.Hashear(msj);
                    firma = rsa.firmar(msjHasheado, rsa.getClavePrivada());
                    msjClavePublica = aes.Encriptar(msj, clave);
                    escritor.println(destinatario);
                    escritor.println(claveSimetrica);
                    System.out.println(claveSimetrica);
                    escritor.println(firma);
                    escritor.println(msjClavePublica);
                    escritor.println(rsa.keyToString(rsa.getClavePublica()));
                }
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static void recibir(String nombreUsuario, Socket socket) {
        try {
            Aes aes = new Aes();
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
            String claveSimetrica = lector.readLine();
            System.out.println(claveSimetrica);
            System.out.println("-------------------------------------------------");
            String firma = lector.readLine();
            String msjClavePublica = lector.readLine();
            PublicKey claveOrigen = rsa.stringToPublic(lector.readLine());
            String claveString = rsa.desencriptadorPublica(claveSimetrica, rsa.getClavePrivada());
            SecretKeySpec clave = aes.base64ToSecretKey(claveString);
            String msjHasheado = rsa.desencriptadorPrivada(firma, claveOrigen);
            String msjAHashear = aes.Desencriptar(msjClavePublica, clave);
            String msjHasheadisimo = rsa.Hashear(msjAHashear);
            if (msjHasheadisimo.equals(msjHasheado)) {
                System.out.println("mensaje de " + nombreUsuario + ": " + msjAHashear);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try (Socket socket = new Socket(DIRECCION_IP_SERVIDOR, PUERTO_SERVIDOR)) {
            // Crea flujos de entrada y salida para la comunicación con el servidor
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);

            while (true) {
                String respuesta = lector.readLine();
                if (respuesta.startsWith("INGRESARNOMBRE")) {
                    // Solicita al usuario que ingrese un nombre de usuario
                    System.out.print("Ingresa un nombre de usuario: ");
                    String nombreUsuario = scanner.nextLine();
                    escritor.println(nombreUsuario);
                    escritor.println(rsa.keyToString(rsa.getClavePublica()));
                } else if (respuesta.startsWith("NOMBREACEPTADO")) {
                    break; // Sale del bucle cuando el nombre de usuario es aceptado
                }
            }

            // Bucle para enviar mensajes al servidor
            new Thread(() -> {
                while (true) {
                    String mensaje = scanner.nextLine();
                    //    System.out.println(mensaje);
                    enviarMensaje(mensaje, socket);
                }
            }).start();

            // Bucle para recibir mensajes del servidor y mostrarlos en la consola
            String nombreUsuarioOrigen;
            while ((nombreUsuarioOrigen = lector.readLine()) != null) {
                recibir(nombreUsuarioOrigen, socket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}