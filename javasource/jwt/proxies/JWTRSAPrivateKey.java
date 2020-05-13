// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package jwt.proxies;

public class JWTRSAPrivateKey extends system.proxies.FileDocument
{
	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "JWT.JWTRSAPrivateKey";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		FileID("FileID"),
		Name("Name"),
		DeleteAfterDownload("DeleteAfterDownload"),
		Contents("Contents"),
		HasContents("HasContents"),
		Size("Size"),
		JWTRSAPrivateKey_JWTRSAKeyPair("JWT.JWTRSAPrivateKey_JWTRSAKeyPair");

		private java.lang.String metaName;

		MemberNames(java.lang.String s)
		{
			metaName = s;
		}

		@java.lang.Override
		public java.lang.String toString()
		{
			return metaName;
		}
	}

	public JWTRSAPrivateKey(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, "JWT.JWTRSAPrivateKey"));
	}

	protected JWTRSAPrivateKey(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject jWTRSAPrivateKeyMendixObject)
	{
		super(context, jWTRSAPrivateKeyMendixObject);
		if (!com.mendix.core.Core.isSubClassOf("JWT.JWTRSAPrivateKey", jWTRSAPrivateKeyMendixObject.getType()))
			throw new java.lang.IllegalArgumentException("The given object is not a JWT.JWTRSAPrivateKey");
	}

	/**
	 * @deprecated Use 'JWTRSAPrivateKey.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static jwt.proxies.JWTRSAPrivateKey initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return jwt.proxies.JWTRSAPrivateKey.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 */
	public static jwt.proxies.JWTRSAPrivateKey initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new jwt.proxies.JWTRSAPrivateKey(context, mendixObject);
	}

	public static jwt.proxies.JWTRSAPrivateKey load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return jwt.proxies.JWTRSAPrivateKey.initialize(context, mendixObject);
	}

	public static java.util.List<jwt.proxies.JWTRSAPrivateKey> load(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String xpathConstraint) throws com.mendix.core.CoreException
	{
		java.util.List<jwt.proxies.JWTRSAPrivateKey> result = new java.util.ArrayList<jwt.proxies.JWTRSAPrivateKey>();
		for (com.mendix.systemwideinterfaces.core.IMendixObject obj : com.mendix.core.Core.retrieveXPathQuery(context, "//JWT.JWTRSAPrivateKey" + xpathConstraint))
			result.add(jwt.proxies.JWTRSAPrivateKey.initialize(context, obj));
		return result;
	}

	/**
	 * @return value of JWTRSAPrivateKey_JWTRSAKeyPair
	 */
	public final jwt.proxies.JWTRSAKeyPair getJWTRSAPrivateKey_JWTRSAKeyPair() throws com.mendix.core.CoreException
	{
		return getJWTRSAPrivateKey_JWTRSAKeyPair(getContext());
	}

	/**
	 * @param context
	 * @return value of JWTRSAPrivateKey_JWTRSAKeyPair
	 */
	public final jwt.proxies.JWTRSAKeyPair getJWTRSAPrivateKey_JWTRSAKeyPair(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		jwt.proxies.JWTRSAKeyPair result = null;
		com.mendix.systemwideinterfaces.core.IMendixIdentifier identifier = getMendixObject().getValue(context, MemberNames.JWTRSAPrivateKey_JWTRSAKeyPair.toString());
		if (identifier != null)
			result = jwt.proxies.JWTRSAKeyPair.load(context, identifier);
		return result;
	}

	/**
	 * Set value of JWTRSAPrivateKey_JWTRSAKeyPair
	 * @param jwtrsaprivatekey_jwtrsakeypair
	 */
	public final void setJWTRSAPrivateKey_JWTRSAKeyPair(jwt.proxies.JWTRSAKeyPair jwtrsaprivatekey_jwtrsakeypair)
	{
		setJWTRSAPrivateKey_JWTRSAKeyPair(getContext(), jwtrsaprivatekey_jwtrsakeypair);
	}

	/**
	 * Set value of JWTRSAPrivateKey_JWTRSAKeyPair
	 * @param context
	 * @param jwtrsaprivatekey_jwtrsakeypair
	 */
	public final void setJWTRSAPrivateKey_JWTRSAKeyPair(com.mendix.systemwideinterfaces.core.IContext context, jwt.proxies.JWTRSAKeyPair jwtrsaprivatekey_jwtrsakeypair)
	{
		if (jwtrsaprivatekey_jwtrsakeypair == null)
			getMendixObject().setValue(context, MemberNames.JWTRSAPrivateKey_JWTRSAKeyPair.toString(), null);
		else
			getMendixObject().setValue(context, MemberNames.JWTRSAPrivateKey_JWTRSAKeyPair.toString(), jwtrsaprivatekey_jwtrsakeypair.getMendixObject().getId());
	}

	@java.lang.Override
	public boolean equals(Object obj)
	{
		if (obj == this)
			return true;

		if (obj != null && getClass().equals(obj.getClass()))
		{
			final jwt.proxies.JWTRSAPrivateKey that = (jwt.proxies.JWTRSAPrivateKey) obj;
			return getMendixObject().equals(that.getMendixObject());
		}
		return false;
	}

	@java.lang.Override
	public int hashCode()
	{
		return getMendixObject().hashCode();
	}

	/**
	 * @return String name of this class
	 */
	public static java.lang.String getType()
	{
		return "JWT.JWTRSAPrivateKey";
	}

	/**
	 * @return String GUID from this object, format: ID_0000000000
	 * @deprecated Use getMendixObject().getId().toLong() to get a unique identifier for this object.
	 */
	@java.lang.Override
	@java.lang.Deprecated
	public java.lang.String getGUID()
	{
		return "ID_" + getMendixObject().getId().toLong();
	}
}
