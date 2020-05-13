// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package jwt.actions;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.mendix.core.Core;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import jwt.proxies.JWTRSAPrivateKey;
import com.mendix.systemwideinterfaces.core.IMendixObject;

/**
 * Use this action to instantiate a private key in case your key pair has been generated by a third party.
 */
public class GenerateRSAPrivateKey extends CustomJavaAction<IMendixObject>
{
	private java.lang.String modulus;
	private java.lang.String privateExponent;

	public GenerateRSAPrivateKey(IContext context, java.lang.String modulus, java.lang.String privateExponent)
	{
		super(context);
		this.modulus = modulus;
		this.privateExponent = privateExponent;
	}

	@java.lang.Override
	public IMendixObject executeAction() throws Exception
	{
		// BEGIN USER CODE
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
		PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(rsaPrivateKey.getEncoded());
		byte[] privateKeyPKCS1 = privateKeyInfo.toASN1Primitive().getEncoded();
		
		JWTRSAPrivateKey privateKey = new JWTRSAPrivateKey(this.context());
		Core.commit(this.context(), privateKey.getMendixObject());
		Core.storeFileDocumentContent(this.context(), privateKey.getMendixObject(), new ByteArrayInputStream(privateKeyPKCS1));
		return privateKey.getMendixObject();
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "GenerateRSAPrivateKey";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
