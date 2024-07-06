package org.cryptomator.secube;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.util.encoders.Hex;

public class Communication {
	
	private static final boolean debug = false;
	
	// Constants for Diffie-Hellman
	private static final BigInteger G = new BigInteger("2");
    private static final BigInteger P = new BigInteger("008b3413e6cde53095290320e1bc37c198bb9ef023308c5ff5ef98b4afb0f429224ceee1ed42f32b290fe49f8f68a81f2e4b0d28998d5842f363da73c2858932148da345aec40b5122142404146e397861b92c597ea134729311673f18fa3e965d9476635173f3479d5438883a3a95dbe31dd2954ec7ee8d0da418effd683063e07", 16);

	public static String main(String mode, String serialNumber, String PIN, String IDVault) throws Exception {

		String pubHex = "0404e02e7c3a6c2013f67a2cc98be3d0b7824afff7d4f1b4deda3c111550f47d7184cbf869d5430ecc772b2cbb91ee185972138ad08c1ea4adc1518c8ccb6d6ac1";
		byte[] pubByte = Hex.decode(pubHex);
	
		// Generate random A
		SecureRandom random = new SecureRandom();
        BigInteger A = new BigInteger(2048, random);
        if(debug) {
	        System.out.println("\nA: " + A);
        }
        
        System.out.println("\nID: " + IDVault);
        
        // Compute K_cryptomator
        BigInteger K_cryptomator = G.modPow(A, P);
        if(debug) {
	        System.out.println("\nK_cryptomator: " + K_cryptomator);
        }
        
        // Starting communication
        String cmd = "../dist/win/CommMIddleware.exe " + mode + " " + serialNumber + " " +  PIN;
		Process process = Runtime.getRuntime().exec(cmd);
		
		// Send [ K_cryptomator, ID_Vault ]
		ProcessUtils.writeOnProcess(process, List.of(K_cryptomator.toString(16), IDVault));
        
        // Receive [ K_secube, DSig_secube, K_enc_vault]
        String sb = ProcessUtils.readFromProcess(process);
        String[] input = sb.split("\n");
        try {
        	String test = input[1];
        } catch (Exception e) {
        	return "Error: Error in the Middleware output";
        }
        if(debug) {
        	System.out.println("\n---------------------------------------------------");
	        System.out.println("ECDS bit length: " + input[0]);
	        System.out.println("\nECDS - HEX format: " + input[1]);
	        System.out.println("\nMAC byte length: " + input[2]);
	        System.out.println("\nMAC - HEX format: " + input[3]);
	        System.out.println("\nIV - HEX format: " + input[4]);
	        System.out.println("\nCYPHERTEXT byte length: " + input[5]);
	        System.out.println("\nCYPHERTEXT - HEX format: " + input[6]);
	        System.out.println("\nPUBLIC KEY MIDDLEWARE bit length: " + input[7]);
	        System.out.println("\nPUBLIC KEY MIDDLEWARE - HEX format: " + input[8]);       
	        System.out.println("---------------------------------------------------\n");
        }      
     
        byte[] ECDSByteFromHex = Hex.decode(input[1]);
        int ECDS_len = Integer.valueOf(input[0]);
        if(ECDSByteFromHex.length != ECDS_len)
        	return "Error: ECDS length is not right";
        
        byte[] Ciphertext = Hex.decode(input[6]);
        int Ciphertext_len = Integer.valueOf(input[5]);
        if(Ciphertext.length != Ciphertext_len)
        	return "Error: Ciphertext length is not right";
        
        byte[] MAC = Hex.decode(input[3]);
        int MAC_len = Integer.valueOf(input[2]);
        if(MAC.length != MAC_len)
        	return "Error: MAC length is not right";
        
        byte[] IV = Hex.decode(input[4]);
        
        BigInteger PK_MIDD = new BigInteger(input[8], 16);
        int PK_MIDD_len = Integer.valueOf(input[7]);
        if(PK_MIDD.toByteArray().length*8 != PK_MIDD_len)
        	return "Error: PK_MIDD length is not right";
        
        if(debug) {
        	System.out.println("\nECDSByteFromHex: " + CryptoUtils.bytesToHex(ECDSByteFromHex));
        	System.out.println("\nArrays.toString(ECDSByteFromHex): " + Arrays.toString(ECDSByteFromHex));
        	System.out.println("\nMAC: " + CryptoUtils.bytesToHex(MAC));
        	System.out.println("\nIV: " + CryptoUtils.bytesToHex(IV));
        	System.out.println("\nCYPHERTEXT: " + CryptoUtils.bytesToHex(Ciphertext));
        	System.out.println("\nPK_MIDD: " + PK_MIDD.toString(16));
        	System.out.println("---------------------------------------------------\n");
        }
        
        // Compute K_simm_cryptomator
        BigInteger K_simm = PK_MIDD.modPow(A, P);
        if(debug) {
	        System.out.println("\nK_simm: " + K_simm);
	        System.out.println("\nK_simm length: " + K_simm.bitLength());
	        System.out.println("\nK_simmHex: " + K_simm.toString(16));
	        System.out.println("---------------------------------------------------\n");
        }
        
        // Compute Hash_cryptomator (AES_key)
        byte[] Hash_cryptomator;
        try {
        	Hash_cryptomator = CryptoUtils.hash(K_simm.toByteArray());
        } catch (Exception e) {
        	//e.printStackTrace();
        	return "Error: Unable to hash the symmetric key";
        }
        
        if(debug) {
        	System.out.println("\nHash_cryptomator: " + CryptoUtils.bytesToHex(Hash_cryptomator));
        }
        
        // Verify DSig_secube
        boolean validSignature = true;
		try {
			validSignature = CryptoUtils.verify(
					/* byte[] message */
					Hash_cryptomator,
					/* byte[] signature */
					ECDSByteFromHex,
					/* PublicKey publicKey */
					pubByte
					);
		} catch (Exception e) {
			//e.printStackTrace();
			return "Error: Unable to verify signature";
		}
		
		System.out.println("\nvalidSignature: " + validSignature);
		
        if (validSignature) {
            // Decrypt K_enc_vault with K_simm_cryptomator
            byte[] decryptedK_VaultBytes;
            try{
            	decryptedK_VaultBytes = CryptoUtils.decryptAES(
            		/* byte[] encryptedData */
            		Ciphertext,
            		/* byte[] key */
            		Hash_cryptomator,
            		/* byte[] iv */
            		IV
            		);
            } catch (Exception e) {
            	//e.printStackTrace();
    			return "Error: Unable to decrypt";
            }
            
            // Use decryptedK_Vault as needed
            System.out.println("\ndecryptedK_Vault: " + CryptoUtils.bytesToHex(decryptedK_VaultBytes));
        
            // Verify MAC of decryptedK_Vault
            boolean validMac = false;
            try{
	            validMac = CryptoUtils.verifyHMACSHA256(
	            		decryptedK_VaultBytes,
	            		MAC,
	            		Hash_cryptomator
	            );
            } catch (Exception e) {
            	//e.printStackTrace();
    			return "Error: Unable to validate MAC";
            }

            System.out.println("\nvalidMac: " + validMac);
            
            return CryptoUtils.bytesToHex(decryptedK_VaultBytes);
        } else {
            // ABORT
            throw new SecurityException("Error: Invalid signature, aborting process.");
        }
	}
}
