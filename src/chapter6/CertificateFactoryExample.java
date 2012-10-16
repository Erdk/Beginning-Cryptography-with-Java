package chapter6;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMWriter;

/**
 * Basic example of using a CertificateFactory.
 */
public class CertificateFactoryExample
{
	
	private static final String DER = "DER";
	private static final String PEM = "PEM";
	
	private static final String outputFormat = PEM;
	
    public static void main(String[] args)
        throws Exception
    {
        // create the keys
        KeyPair          pair = Utils.generateRSAKeyPair();
        
        // create the input stream
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        if (outputFormat.equals(DER)) {
        	bOut.write(X509V1CreateExample.generateV1Certificate(pair).getEncoded());
        }
        else if (outputFormat.equals(PEM)) {
            PEMWriter pemWriter = new PEMWriter(new OutputStreamWriter(bOut));
            pemWriter.writeObject(X509V1CreateExample.generateV1Certificate(pair));
            pemWriter.close();
        }
        
        bOut.close();
        
        // Print the contents of bOut
        
        System.out.println(outputFormat.equals(DER) ? "DER-format:" : "PEM-format:");
        
        System.out.println(Utils.toString(bOut.toByteArray()));
        
        InputStream in = new ByteArrayInputStream(bOut.toByteArray());
        
        // create the certificate factory
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        
        // read the certificate
        X509Certificate    x509Cert = (X509Certificate)fact.generateCertificate(in);
        
        System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
    }
}
