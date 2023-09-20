import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Rsa {

    private PrivateKey clavePrivada;
    private PublicKey clavePublica;

    public  Rsa () {
        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");//creamos generador de las dos claves de tipo rsa
            generador.initialize(1024);//inicializamos la longitud de las claves
            KeyPair parClavaes = generador.generateKeyPair();
            clavePrivada = parClavaes.getPrivate();
            clavePublica = parClavaes.getPublic();
        } catch (Exception ignored){
        }
    }

    public PrivateKey getClavePrivada() {
        return clavePrivada;
    }

    public void setClavePrivada(PrivateKey clavePrivada) {
        this.clavePrivada = clavePrivada;
    }

    public PublicKey getClavePublica() {
        return clavePublica;
    }

    public void setClavePublica(PublicKey clavePublica) {
        this.clavePublica = clavePublica;
    }

    public static String Hashear(String mensaje) throws NoSuchAlgorithmException {
        String hasheado;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(mensaje.getBytes(StandardCharsets.UTF_8));
        hasheado = DatatypeConverter.printHexBinary(digest).toLowerCase();
        return hasheado;
    }
    /*------------
    ENCRIPTACION
    ------------*/
    public String encriptador (String msj , PublicKey publicKey) throws Exception{
        byte[] pasajeMsjABytes = msj.getBytes();//Obtener los bytes de msj
        //Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");//instanciamos el cifrado
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, publicKey);//le decimos al cifrado que va a hacer en este caso que encripte
        byte[] msjEnBytesEncriptado = c.doFinal(pasajeMsjABytes);//le decimos que encripte el msj
        return codificador(msjEnBytesEncriptado);
    }
    public String firmar (String msj, PrivateKey privateKey) throws Exception{
        byte[] pasajeMsjABytes = msj.getBytes();//Obtener los bytes de msj
        //Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");//instanciamos el cifrado
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, privateKey);//le decimos al cifrado que va a hacer en este caso que encripte
        byte[] msjEnBytesEncriptado = c.doFinal(pasajeMsjABytes);//le decimos que encripte el msj
        return codificador(msjEnBytesEncriptado);
    }
    public String codificador(byte[] data){
        return Base64.getEncoder().encodeToString(data);//pasamos estos bytes a String
    }
/*---------------
DESENCRIPTACION
---------------*/

    public String desencriptadorPublica (String msjEncriptado, PrivateKey privateKey) throws Exception {
        byte[] bytesEncriptados = descodificador(msjEncriptado);
        //Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");//instanciamos el cifrado
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, privateKey);//le decimos al cifrado que va a hacer en este caso que desencripte
        byte[] msjDesencriptado = c.doFinal(bytesEncriptados);
        return  new String(msjDesencriptado, "UTF8");
    }
    public String desencriptadorPrivada (String msjEncriptado, PublicKey publicKey) throws Exception {
        byte[] bytesEncriptados = descodificador(msjEncriptado);
        //Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");//instanciamos el cifrado
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, publicKey);//le decimos al cifrado que va a hacer en este caso que desencripte
        byte[] msjDesencriptado = c.doFinal(bytesEncriptados);
        return  new String(msjDesencriptado, "UTF8");
    }
    public byte[] descodificador(String data){

        return Base64.getDecoder().decode(data); //pasamos este String a bytes
    }

    public  String keyToString(Key llave){

        return Base64.getEncoder().encodeToString(llave.getEncoded());

    }


    public  PublicKey stringToPublic(String encoded) throws InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] decoded = Base64.getDecoder().decode(encoded);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        PublicKey original = (PublicKey) factory.generatePublic(new X509EncodedKeySpec(decoded));

        return original;

    }


    public  PrivateKey stringToPrivate(String encoded) throws InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] decoded = Base64.getDecoder().decode(encoded.getBytes());

        KeyFactory factory = KeyFactory.getInstance("RSA");

        PrivateKey original = (PrivateKey) factory.generatePrivate(new X509EncodedKeySpec(decoded));

        return original;

    }
    /*public static void main(String[] args) {
        RSA rsa = new RSA();

        try {
            String msjEncriptado = rsa.encriptador("Hola cata, anda a bañarte", rsa.getClavePublica());
            String msjDesencriptado = rsa.desencriptadorPublica(msjEncriptado, rsa.getClavePrivada());

            System.out.println("Mensaje encriptado:\n" + msjEncriptado);
            System.out.println("Mensaje desencriptado:\n" + msjDesencriptado);

        } catch (Exception ingored) {
        }
    }*/

}