package chapter6;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import sun.misc.BASE64Encoder;


/**
 * Basic X.509 V3 Certificate creation with TLS flagging.
 */
public class X509V3CreateExample
{
	@SuppressWarnings("deprecation")
	public static X509Certificate generateV3Certificate(KeyPair pair)
        throws InvalidKeyException, NoSuchProviderException, SignatureException
    {
        // generate the certificate
        X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
        certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        
        certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test")));
        
        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }
    
	public static X509Certificate generateX509v3Certificate(KeyPair pair) throws CertificateException, IOException, OperatorCreationException {
    	
    	X509Certificate generatedCertificate = null;
    	
    	
    	/**
    	 * org.bouncycastle.cert.X509v3CertificateBuilder.X509v3CertificateBuilder(
    	 * 	X500Name issuer, 
    	 * 	BigInteger serial, 
    	 *  Date notBefore, 
    	 *  Date notAfter, 
    	 *  X500Name subject, 
    	 *  SubjectPublicKeyInfo publicKeyInfo)
    	 */
    	
    	// Issuer's Distinguished Name
    	String issuerDN = "CN=www.bouncycastle.org, OU=Bouncy Castle, O=Legions, C=AU";
		X500Name issuer = new X500Name(issuerDN);
    	
		// The serial for this certificate. The issuer's DN and this serial uniquely identifies this certificate.
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		
		// The date before which the certificate is not valid
		Date notBefore = new Date(System.currentTimeMillis() - 50000);
		
		// The date after which the certificate is not valid
		Date notAfter = new Date(System.currentTimeMillis() + 50000);
		
		// The subject's (the principal the certificate is issued to) Distinguished Name
		// A self-signed certificate implies that the issuer is also the subject
		X500Name subject = new X500Name(issuerDN);
		
//		AlgorithmIdentifier algId = new AlgorithmIdentifier(objectId )
//		
//		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, publicKey)
//		
//    	certBuilder.
    	
		AlgorithmIdentifier algId = new AlgorithmIdentifier(X509ObjectIdentifiers.id_ea_rsa);
		SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(algId, pair.getPublic().getEncoded());
		
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
		
		
		// try to add an extension to the certificate
		
		// this is really quite rubbish
		ASN1ObjectIdentifier oid = org.bouncycastle.asn1.x509.Extension.policyConstraints;
		ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
		ASN1Encodable extension;
		
		// how do I create an ASN1Encodable object..? 
		
		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(pair.getPrivate());
		X509CertificateHolder certificateHolder = certBuilder.build(signer);
    	
		
		System.out.println(certificateHolder.getVersionNumber());
		System.out.println(certificateHolder.getIssuer());
		System.out.println(certificateHolder.getSubject());
		System.out.println(certificateHolder.getExtensionOIDs());
		BASE64Encoder b64 = new BASE64Encoder();
		
		System.out.println(b64.encode(certificateHolder.getEncoded()));
//		
		return null;
//		Certificate asn1Structure = certificateHolder.toASN1Structure();
//		
//		CertificateFactory cf = new CertificateFactory();
//		
//		ByteArrayInputStream bis = new ByteArrayInputStream(certificateHolder.getEncoded());
//		
//		return (X509Certificate) cf.engineGenerateCertificate(bis);
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        // create the keys
        KeyPair         pair = Utils.generateRSAKeyPair();
        
        // generate the certificate
        X509Certificate cert = generateV3Certificate(pair);
//        X509Certificate cert = generateX509v3Certificate(pair);
        
        // show some basic validation
        cert.checkValidity(new Date());

        cert.verify(cert.getPublicKey());

        System.out.println("valid certificate generated");
        
        // store the certificate in a file, encoded in binary DER format
        FileOutputStream fos = new FileOutputStream("/home/erik/certificates/test.der");
        fos.write(cert.getEncoded());
        fos.close();
    }
}
