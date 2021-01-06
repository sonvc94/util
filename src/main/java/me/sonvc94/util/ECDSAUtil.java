package me.sonvc94.util;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECCDSA signature verification tools
 */
public class ECDSAUtil {

    private static final String SIGNALGORITHMS = "SHA256withECDSA";
    private static final String ALGORITHM = "EC";
    private static final String SECP256K1 = "secp256k1";


    public static void main(String[] args) throws Exception {

        // Generate public key and private key
        KeyPair keyPair1 = getKeyPair();
        PublicKey publicKey1 = keyPair1.getPublic();
        PrivateKey privateKey1 = keyPair1.getPrivate();
        //Key to hexadecimal string
        String publicKey = HexUtil.encodeHexString(publicKey1.getEncoded());
        String privateKey = HexUtil.encodeHexString(privateKey1.getEncoded());
        System.out.println("Generate public key:" + publicKey);
        System.out.println("Generate private key:" + privateKey);
        //Hexadecimal string to key object
        PrivateKey privateKey2 = getPrivateKey(privateKey);
        PublicKey publicKey2 = getPublicKey(publicKey);
        //Signature and verification
        String data1 = "Cộng hòa xã hội chủ nghĩa Việt Nam, Cộng hòa xã hội chủ nghĩa Việt Nam, Cộng hòa xã hội chủ " +
                "nghĩa Việt Nam, Cộng hòa xã hội chủ nghĩa Việt Nam, Cộng hòa xã hội chủ nghĩa Việt Nam, Cộng hòa xã " +
                "hội chủ nghĩa Việt Nam, Cộng hòa xã hội chủ nghĩa Việt Nam";
        String signECDSA1 = signECDSA(privateKey1, data1);
        System.out.println("sign data: " + signECDSA1);
        boolean verifyECDSA = verifyECDSA(publicKey2, signECDSA1, data1);
        System.out.println("verification result:" + verifyECDSA);
    }

    /**
     *
     * @param privateKey private key
     * @param data       data
     * @return
     */
    public static String signECDSA(PrivateKey privateKey, String data) {
        String result = "";
        try {
            //Execute signature
            Signature signature = Signature.getInstance(SIGNALGORITHMS);
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            byte[] sign = signature.sign();
            return HexUtil.encodeHexString(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Verification
     *
     * @param publicKey public key
     * @param signed    signature
     * @param data      data
     * @return
     */
    public static boolean verifyECDSA(PublicKey publicKey, String signed, String data) {
        try {
            //Verify signature
            Signature signature = Signature.getInstance(SIGNALGORITHMS);
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            byte[] hex = HexUtil.decode(signed);
            boolean bool = signature.verify(hex);
            return bool;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * From string to private key
     *
     * @param key private key string
     * @return
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {

        byte[] bytes = DatatypeConverter.parseHexBinary(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * From string to publicKey
     *
     * @param key public key string
     * @return
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {

        byte[] bytes = DatatypeConverter.parseHexBinary(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }


    /**
     * Generate key pair
     *
     * @return
     * @throws Exception
     */
    public static KeyPair getKeyPair() throws Exception {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SECP256K1);
        KeyPairGenerator kf = KeyPairGenerator.getInstance(ALGORITHM);
        kf.initialize(ecSpec, new SecureRandom());
        KeyPair keyPair = kf.generateKeyPair();
        return keyPair;
    }

}
