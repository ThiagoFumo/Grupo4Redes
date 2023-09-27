import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import javax.crypto.spec.SecretKeySpec;

public class Aes {

    private SecretKeySpec secretKeySpec;

    public Aes() {
    }
    /*public static void main(String[] args) {
        String encriptada = "";
        String aEnccriptar = "";
        Aes aes = new Aes();
        aEnccriptar = JOptionPane.showInputDialog("Ingresa la cadena a encriptar: ");
        encriptada = aes.Encriptar(aEnccriptar);
        JOptionPane.showMessageDialog(null, encriptada);
        JOptionPane.showMessageDialog(null, aes.Desencriptar(encriptada));

    }*/

    public SecretKeySpec getSecretKeySpec() {
        return secretKeySpec;
    }

    public void setSecretKeySpec(SecretKeySpec secretKeySpec) {
        this.secretKeySpec = secretKeySpec;
    }

    public SecretKeySpec getKeyFromKeyGenerator(String cipher, int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(cipher);
            keyGenerator.init(keySize);
            return (SecretKeySpec) keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    // Encriptar
    public String Encriptar(String encriptar, SecretKeySpec clave) {

        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, clave);

            byte [] cadena = encriptar.getBytes("UTF-8");
            byte [] encriptada = cipher.doFinal(cadena);
            String cadena_encriptada = Base64.encode(encriptada);
            return cadena_encriptada;



        } catch (Exception e) {
            return "";
        }
    }

    public static String secretKeyToBase64(SecretKey secretKey) {
        byte[] keyBytes = secretKey.getEncoded();
        return java.util.Base64.getEncoder().encodeToString(keyBytes);
        //return Base64.getEncoder().encodeToString(keyBytes);
    }
    public static SecretKeySpec base64ToSecretKey(String base64Key) {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(base64Key);
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES"); // Cambia "AES" por el algoritmo de tu clave secreta
    }
    // Des-encriptación
    public String Desencriptar(String desencriptar, SecretKeySpec clave) {

        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, clave);

            byte [] cadena = Base64.decode(desencriptar);
            byte [] desencriptacioon = cipher.doFinal(cadena);
            String cadena_desencriptada = new String(desencriptacioon);
            return cadena_desencriptada;

        } catch (Exception e) {
            return "";
        }
    }
}