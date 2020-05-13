// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package auth0.proxies;

public class JWKS
{
	private final com.mendix.systemwideinterfaces.core.IMendixObject jWKSMendixObject;

	private final com.mendix.systemwideinterfaces.core.IContext context;

	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "Auth0.JWKS";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		Keys_JWKS("Auth0.Keys_JWKS");

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

	public JWKS(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, "Auth0.JWKS"));
	}

	protected JWKS(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject jWKSMendixObject)
	{
		if (jWKSMendixObject == null)
			throw new java.lang.IllegalArgumentException("The given object cannot be null.");
		if (!com.mendix.core.Core.isSubClassOf("Auth0.JWKS", jWKSMendixObject.getType()))
			throw new java.lang.IllegalArgumentException("The given object is not a Auth0.JWKS");

		this.jWKSMendixObject = jWKSMendixObject;
		this.context = context;
	}

	/**
	 * @deprecated Use 'JWKS.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static auth0.proxies.JWKS initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return auth0.proxies.JWKS.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 */
	public static auth0.proxies.JWKS initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new auth0.proxies.JWKS(context, mendixObject);
	}

	public static auth0.proxies.JWKS load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return auth0.proxies.JWKS.initialize(context, mendixObject);
	}

	/**
	 * Commit the changes made on this proxy object.
	 */
	public final void commit() throws com.mendix.core.CoreException
	{
		com.mendix.core.Core.commit(context, getMendixObject());
	}

	/**
	 * Commit the changes made on this proxy object using the specified context.
	 */
	public final void commit(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		com.mendix.core.Core.commit(context, getMendixObject());
	}

	/**
	 * Delete the object.
	 */
	public final void delete()
	{
		com.mendix.core.Core.delete(context, getMendixObject());
	}

	/**
	 * Delete the object using the specified context.
	 */
	public final void delete(com.mendix.systemwideinterfaces.core.IContext context)
	{
		com.mendix.core.Core.delete(context, getMendixObject());
	}
	/**
	 * @return value of Keys_JWKS
	 */
	public final auth0.proxies.Keys getKeys_JWKS() throws com.mendix.core.CoreException
	{
		return getKeys_JWKS(getContext());
	}

	/**
	 * @param context
	 * @return value of Keys_JWKS
	 */
	public final auth0.proxies.Keys getKeys_JWKS(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		auth0.proxies.Keys result = null;
		com.mendix.systemwideinterfaces.core.IMendixIdentifier identifier = getMendixObject().getValue(context, MemberNames.Keys_JWKS.toString());
		if (identifier != null)
			result = auth0.proxies.Keys.load(context, identifier);
		return result;
	}

	/**
	 * Set value of Keys_JWKS
	 * @param keys_jwks
	 */
	public final void setKeys_JWKS(auth0.proxies.Keys keys_jwks)
	{
		setKeys_JWKS(getContext(), keys_jwks);
	}

	/**
	 * Set value of Keys_JWKS
	 * @param context
	 * @param keys_jwks
	 */
	public final void setKeys_JWKS(com.mendix.systemwideinterfaces.core.IContext context, auth0.proxies.Keys keys_jwks)
	{
		if (keys_jwks == null)
			getMendixObject().setValue(context, MemberNames.Keys_JWKS.toString(), null);
		else
			getMendixObject().setValue(context, MemberNames.Keys_JWKS.toString(), keys_jwks.getMendixObject().getId());
	}

	/**
	 * @return the IMendixObject instance of this proxy for use in the Core interface.
	 */
	public final com.mendix.systemwideinterfaces.core.IMendixObject getMendixObject()
	{
		return jWKSMendixObject;
	}

	/**
	 * @return the IContext instance of this proxy, or null if no IContext instance was specified at initialization.
	 */
	public final com.mendix.systemwideinterfaces.core.IContext getContext()
	{
		return context;
	}

	@java.lang.Override
	public boolean equals(Object obj)
	{
		if (obj == this)
			return true;

		if (obj != null && getClass().equals(obj.getClass()))
		{
			final auth0.proxies.JWKS that = (auth0.proxies.JWKS) obj;
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
		return "Auth0.JWKS";
	}

	/**
	 * @return String GUID from this object, format: ID_0000000000
	 * @deprecated Use getMendixObject().getId().toLong() to get a unique identifier for this object.
	 */
	@java.lang.Deprecated
	public java.lang.String getGUID()
	{
		return "ID_" + getMendixObject().getId().toLong();
	}
}