import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
public class CompareCertCsr{

    public static void main(String[] args) throws Exception{
	if( args.length == 1){
	    System.out.println("Reading Certificate\n");
	    main2(args);
	    return;
	}
	if(args.length != 2){
	    System.out.println("Need the Certificate and/or CSR files\n");
	    return;
	}

	Security.addProvider(new BouncyCastleProvider());

	CertificateFactory cfac = CertificateFactory.getInstance("X.509");
	X509Certificate merchantCert;

	PKCS10CertificationRequest csr;
	try(FileInputStream certStream = new FileInputStream(args[0]); FileInputStream csrStream = new FileInputStream(args[1]) ){
	    merchantCert = (X509Certificate)cfac.generateCertificate(certStream);
	    try(
		    Reader pemReader = new BufferedReader(new InputStreamReader( csrStream ));
		    PEMParser pemParser = new PEMParser(pemReader) ){
		csr = (PKCS10CertificationRequest)pemParser.readObject();
	    }
	}


	StringWriter output = new StringWriter();
	PemWriter pemWriter = new PemWriter(output);
	PemObject pkPemObject = new PemObject("PUBLIC KEY", csr.getSubjectPublicKeyInfo().getEncoded());
	pemWriter.writeObject(pkPemObject);
	pemWriter.close();
	System.out.println(output.toString());

	String publicKeyPEM = output.toString().replace("-----BEGIN PUBLIC KEY-----\n", "");
	publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "").replace("\n", "");

	byte [] decoded = Base64.getDecoder().decode(publicKeyPEM);
	KeyFactory keyFactory = KeyFactory.getInstance("EC");
	X509EncodedKeySpec csrStream = new X509EncodedKeySpec( decoded);
	PublicKey csrKey = keyFactory.generatePublic(csrStream);

	System.out.println("Certificate:\n" + merchantCert.toString() + "\n end of Certificate\n");
	System.out.println("\nCSR PublicKey:\n" + csrKey.toString() + "\n end of CSR PublicKey\n");

	if(Arrays.equals(merchantCert.getPublicKey().getEncoded(), csrKey.getEncoded())){
	    System.out.println("\nPublic Key from Certificate Matches the one from the CSR");
	}else{
	    System.out.println("\nPublic Key from Certificate does NOT match the one from the CSR");
	}

	MessageDigest md = MessageDigest.getInstance("SHA256");

	System.out.println("\nHash of the Certificate\n\n" + Base64.getEncoder().encodeToString(md.digest(merchantCert.getPublicKey().getEncoded())));
    }

    public static void main2(String[] args) throws Exception{
	if(args.length != 1){
	    System.out.println("Need the Certificate in hex\n");
	    return;
	}
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	String hexBytes = args[0];
	java.security.cert.CertificateFactory cfac = CertificateFactory.getInstance("X.509");

	byte[] keyBytes = javax.xml.bind.DatatypeConverter.parseHexBinary(hexBytes);
	X509Certificate merchantCert = (X509Certificate)cfac.generateCertificate(new ByteArrayInputStream( keyBytes ) );
	System.out.println(merchantCert.toString());

	MessageDigest md = MessageDigest.getInstance("SHA256");

	System.out.println("\nHash of the Certificate\n\n" + Base64.getEncoder().encodeToString(md.digest(merchantCert.getPublicKey().getEncoded())));
    }
}
