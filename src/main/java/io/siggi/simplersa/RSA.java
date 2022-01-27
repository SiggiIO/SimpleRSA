package io.siggi.simplersa;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;

/**
 * RSA utility for encrypting and decrypting blocks of information.
 *
 * @author Sigurdur Helgason
 */
public class RSA {
	private RSA() {
	}

	/**
	 * Encrypt a block of data using the public key, to be decrypted later on using the private key.
	 */
	public static byte[] encrypt(byte[] data, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Decrypt a block of data using the private key.
	 */
	public static byte[] decrypt(byte[] data, PrivateKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Encrypt a block of data using the private key, to be decrypted later on using the public key.
	 */
	public static byte[] encrypt(byte[] data, PrivateKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Decrypt a block of data using the private key.
	 */
	public static byte[] decrypt(byte[] data, PublicKey key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return cipher.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Sign some data.
	 */
	public static byte[] sign(byte[] data, PrivateKey key, String algorithm) {
		try {
			Signature signature = Signature.getInstance(algorithm);
			signature.initSign(key);
			signature.update(data);
			return signature.sign();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Verify a signature.
	 */
	public static boolean verify(byte[] data, PublicKey key, byte[] signature, String algorithm) {
		try {
			Signature publicSignature = Signature.getInstance(algorithm);
			publicSignature.initVerify(key);
			publicSignature.update(data);
			return publicSignature.verify(signature);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
