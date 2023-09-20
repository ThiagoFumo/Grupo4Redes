import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

public class Servidor {
    private static final int PUERTO = 12345;
    private static Rsa rsa = new Rsa();
    private static HashMap<String, PublicKey> clavesUsuarios = new HashMap<>();
    private static Set<String> nombresUsuarios = new HashSet<>();
    private static Map<String, PrintWriter> escritoresClientes = new HashMap<>();

    public static void main(String[] args) {
        System.out.println("El servidor está en funcionamiento...");
        try (ServerSocket socketServidor = new ServerSocket(PUERTO)) {
            while (true) {
                new ManejadorCliente(socketServidor.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ManejadorCliente extends Thread {
        private Socket socket;
        private PrintWriter escritor;
        private String nombreUsuario;

        public ManejadorCliente(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                escritor = new PrintWriter(socket.getOutputStream(), true);
                while (true) {
                    escritor.println("INGRESARNOMBRE");
                    nombreUsuario = lector.readLine();
                    PublicKey publicKey = rsa.stringToPublic(lector.readLine());
                    if (nombreUsuario == null) {
                        return;
                    }
                    synchronized (nombresUsuarios) {
                        if (!nombresUsuarios.contains(nombreUsuario)) {
                            nombresUsuarios.add(nombreUsuario);
                            escritoresClientes.put(nombreUsuario, escritor);
                            clavesUsuarios.put(nombreUsuario, publicKey);
                            break;
                        }
                    }
                }
                escritor.println("NOMBREACEPTADO");

                String mensaje;
                while ((mensaje = lector.readLine()) != null){
                    escritor.println(rsa.keyToString(clavesUsuarios.get(mensaje)));
                    mensaje = null;
                    String destinatario = lector.readLine();
                    System.out.println(destinatario);
                    String firma = lector.readLine();
                    System.out.println(firma);
                    System.out.println("-----------------------------------------------------");
                    String msjClavePublica = lector.readLine();
                    System.out.println(msjClavePublica);
                    System.out.println("-----------------------------------------------------");
                    String claveOrigen = lector.readLine();
                    System.out.println(msjClavePublica);
                    System.out.println("------------------------------------------------------");
                    PrintWriter escritorDestinatario = escritoresClientes.get(destinatario);
                    if (escritorDestinatario != null) {
                        System.out.println("ENVIA EL SERVIDOR");
                        escritorDestinatario.println(nombreUsuario);
                        System.out.println(nombreUsuario);
                        System.out.println("-----------------------------------------------");
                        escritorDestinatario.println(firma);
                        System.out.println(firma);
                        System.out.println("------------------------------------------------");;
                        escritorDestinatario.println(msjClavePublica);
                        System.out.println(msjClavePublica);
                        System.out.println("-----------------------------------------------------");
                        escritorDestinatario.println(claveOrigen);
                        System.out.println(claveOrigen);
                        System.out.println("-------------------------------------------------------");
                    }
                }
                /*while ((mensaje = lector.readLine()) != null) {
                    if (mensaje.startsWith("@")) {
                        String[] partes = mensaje.split(" ", 2);
                        if (partes.length > 1) {
                            String destinatario = partes[0].substring(1);
                            String mensajePrivado = partes[1];
                            PrintWriter escritorDestinatario = escritoresClientes.get(destinatario);
                            if (escritorDestinatario != null) {
                                escritorDestinatario.println("Mensaje privado de " + nombreUsuario + ": " + mensajePrivado);
                            }
                        }
                    }
                }*/
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } finally {
                // Cuando el cliente se desconecta, elimina su nombre de usuario y cierra la conexión
                if (nombreUsuario != null) {
                    nombresUsuarios.remove(nombreUsuario);
                    escritoresClientes.remove(nombreUsuario);
                }
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}