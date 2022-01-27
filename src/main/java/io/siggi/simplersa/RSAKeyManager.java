package io.siggi.simplersa;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA utility for loading and saving keys.
 *
 * @author Sigurdur Helgason
 */
public class RSAKeyManager {
	private RSAKeyManager() {
	}
	/**
	 * Generates a key pair with the specified number of bits.
	 *
	 * @param bits number of bits for the key pair.
	 * @return the key pair
	 */
	public static KeyPair generate(int bits) throws InvalidAlgorithmParameterException {
		try {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
			RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4);
			keygen.initialize(spec);
			return keygen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Saves a public key.
	 */
	public static byte[] savePublic(PublicKey publicKey) {
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey.getEncoded());
		return publicSpec.getEncoded();
	}

	/**
	 * Saves a private key.
	 */
	public static byte[] savePrivate(PrivateKey privateKey) {
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		return privateSpec.getEncoded();
	}

	/**
	 * Loads a public key.
	 */
	public static PublicKey loadPublic(byte[] key) throws InvalidKeySpecException {
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

	/**
	 * Loads a private key.
	 */
	public static PrivateKey loadPrivate(byte[] key) throws InvalidKeySpecException {
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}
}
