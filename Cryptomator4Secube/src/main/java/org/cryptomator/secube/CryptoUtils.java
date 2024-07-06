package org.cryptomator.secube;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public static final String CURVE = "secp256k1";
    public static final String ALG = "ECDSA";
    public static final String ENC_ALG= "AES";
    public static final String HASH_ALG= "SHA-256";
    public static final String ECDSA_ALG= "SHA256withECDSA";
    public static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array to convert.
     * @return The hexadecimal string representing the byte array.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            //sb.append(String.format("0x%02x ", b));
        	sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Verifies a signature using a public key.
     *
     * @param message The message whose signature needs to be verified.
     * @param signature The signature to verify.
     * @param publicKey The public key used to verify the signature.
     * @return true if the signature is valid, false otherwise.
     * @throws Exception If an error occurs during the verification of the signature.
     */
    public static boolean verify(byte[] message, byte[] signature, byte[] publicKey) throws Exception {

        // Extract r and s from the signature
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 4, 36));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 38, 70));
        BigInteger[] rs = {r, s};
        
        // Initialize the signer
        ECDSASigner signer = new ECDSASigner();
        X9ECParameters params = SECNamedCurves.getByName(CURVE);
        ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(publicKey), ecParams);
        signer.init(false, pubKeyParams);
        return signer.verifySignature(message, rs[0].abs(), rs[1].abs());
    }
    
    /**
     * Computes the hash of a byte array using SHA-256.
     *
     * @param data The byte array to hash.
     * @return The SHA-256 hash of the byte array.
     */
    public static byte[] hash(byte[] data) throws Exception {
    	Digest digest = new SHA256Digest();
    	digest.update(data, 0, data.length);
    	
    	byte[] result = new byte[digest.getDigestSize()];
    	digest.doFinal(result, 0);
		return result;
	}
    
    /**
     * Decrypts a byte array using AES in CBC mode with PKCS5 padding.
     *
     * @param encryptedData The encrypted data to decrypt.
     * @param key The 32-byte AES key (AES-256).
     * @param iv The 16-byte initialization vector (IV).
     * @return The decrypted data.
     * @throws IllegalArgumentException If the length of the key or IV is incorrect.
     * @throws RuntimeException If an error occurs during decryption.
     */
    public static byte[] decryptAES(byte[] encryptedData, byte[] key, byte[] iv) {
		
    	if (key.length != 32) {
            throw new IllegalArgumentException("Invalid AES key length (must be 32 bytes for AES-256).");
        }

        // Verifica che la lunghezza dell'IV sia corretta
        if (iv.length != 16) {
            throw new IllegalArgumentException("Invalid IV length (must be 16 bytes for AES).");
        }
    	
    	try {
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, ENC_ALG);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
	        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
	        return cipher.doFinal(encryptedData);
	    } catch (Exception e) {
	        throw new RuntimeException(e);
	    }
	}
    
    /**
     * Verifies an HMAC-SHA256.
     *
     * @param message   The original message bytes.
     * @param mac       The MAC bytes to verify.
     * @param key       The key bytes.
     * @return True if the MAC is valid, false otherwise.
     * @throws Exception If an error occurs during verification.
     */
    public static boolean verifyHMACSHA256(byte[] message, byte[] mac, byte[] key) throws Exception {
        // Initialize the HMAC with SHA-256
        Mac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        
        // Update the HMAC with the message
        hmac.update(message, 0, message.length);

        // Compute the MAC
        byte[] computedMac = new byte[hmac.getMacSize()];
        hmac.doFinal(computedMac, 0);

        // Compare the computed MAC with the provided MAC
        return java.util.Arrays.equals(computedMac, mac);
    }
}
