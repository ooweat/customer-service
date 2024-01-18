package kr.co.ooweat.auth.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
@Slf4j
public class EncryptModule {
	public static final String JWT_SECRET_KEY = "ooweat##";
	public static final String AUTH_SIGN_KEY = "UBCnJWTKey";
	public static final String ISSUER = "UBCnAPI#";

	//쿠폰 발권을 위한 암복호화 키
	private static String keyBase64 = "DWIzFkO22qfVMgx2fIsxOXnwz10pRuZfFJBvf4RS3eY=";
	private static String ivBase64 = "AcynMwikMkW4c7+mHtwtfw==";
	
	public static String encryptAES256(String msg) throws Exception {
	    SecureRandom random = new SecureRandom();
	    byte bytes[] = new byte[20];
	    random.nextBytes(bytes);
	    byte[] saltBytes = bytes;

	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    PBEKeySpec spec = new PBEKeySpec(JWT_SECRET_KEY.toCharArray(), saltBytes, 70000, 256);

	    SecretKey secretKey = factory.generateSecret(spec);
	    SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, secret);
	    AlgorithmParameters params = cipher.getParameters();
	    byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
	    byte[] encryptedTextBytes = cipher.doFinal(msg.getBytes("UTF-8"));
	    byte[] buffer = new byte[saltBytes.length + ivBytes.length + encryptedTextBytes.length];
	    System.arraycopy(saltBytes, 0, buffer, 0, saltBytes.length);
	    System.arraycopy(ivBytes, 0, buffer, saltBytes.length, ivBytes.length);
	    System.arraycopy(encryptedTextBytes, 0, buffer, saltBytes.length + ivBytes.length, encryptedTextBytes.length);

	    return Base64.getEncoder().encodeToString(buffer);

	}

	// 복호화 Method
	public static String decryptAES256(String msg) throws Exception {
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(msg));
	    byte[] saltBytes = new byte[20];
	    buffer.get(saltBytes, 0, saltBytes.length);

	    byte[] ivBytes = new byte[cipher.getBlockSize()];
	    buffer.get(ivBytes, 0, ivBytes.length);
	    byte[] encryoptedTextBytes = new byte[buffer.capacity() - saltBytes.length - ivBytes.length];
	    buffer.get(encryoptedTextBytes);

	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    PBEKeySpec spec = new PBEKeySpec(JWT_SECRET_KEY.toCharArray(), saltBytes, 70000, 256);

	    SecretKey secretKey = factory.generateSecret(spec);
	    SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

	    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
	    byte[] decryptedTextBytes = cipher.doFinal(encryoptedTextBytes);

	    return new String(decryptedTextBytes);

	}

	//TODO: 쿠폰에서 사용하는 암호화 체계(Target: phone)/ API에서 쿠폰 발권할 경우에는 연락처를 암호화하지 않음
	public static String couponEncrypt(String plaintext) throws Exception {
		byte[] plaintextArray = plaintext.getBytes(StandardCharsets.UTF_8);
		byte[] keyArray = DatatypeConverter.parseBase64Binary(keyBase64);
		byte[] iv = DatatypeConverter.parseBase64Binary(ivBase64);
		SecretKeySpec secretKey = new SecretKeySpec(keyArray, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(1, secretKey, new IvParameterSpec(iv));
		return new String(DatatypeConverter.printBase64Binary(cipher.doFinal(plaintextArray)));
	}
	public static String couponDecrypt(String ciphertext) throws Exception {
		byte[] ciphertextArray = DatatypeConverter.parseBase64Binary(ciphertext);
		byte[] keyArray = DatatypeConverter.parseBase64Binary(keyBase64);
		byte[] iv = DatatypeConverter.parseBase64Binary(ivBase64);
		SecretKeySpec secretkey = new SecretKeySpec(keyArray, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(2, secretkey, new IvParameterSpec(iv));
		return new String(cipher.doFinal(ciphertextArray));
	}

	public static boolean jwtValid(String token, String perId){
		DecodedJWT decodedJWT = JWT.decode(token);
		if(! decodedJWT.getIssuer().contains(ISSUER)){
			return false;
		} else if (! decodedJWT.getIssuer().contains(perId)){
			return false;
		} else if(decodedJWT.getExpiresAt().before(new Date(System.currentTimeMillis()))){
			return false;
		}
		return true;
	}

	public static void main(String args[]) {
		try {
			log.info("Company Seq 암호화: {}", encryptAES256("770"));
			log.info("복호화: {}", decryptAES256("DWIzFkO22qfVMgx2fIsxOXnwz10pRuZfFJBvf4RS3eY"));
//			String str="D90164";
//			int len=Integer.parseInt(str.substring(2,4),16);
//			System.out.println(Integer.parseInt(str.substring(2,4),16)*2);
//			System.out.println(str.substring(4).getBytes("UTF-8").length);
//			System.out.println(str.substring(4));
//			System.out.println(String.format("%02X",str.substring(4).getBytes("UTF-8").length / 2 ));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
