// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package jwt.proxies;

public class PublicClaimBoolean extends jwt.proxies.PublicClaim
{
	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "JWT.PublicClaimBoolean";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		Value("Value"),
		Claim("Claim"),
		Claim_JWT("JWT.Claim_JWT");

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

	public PublicClaimBoolean(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, "JWT.PublicClaimBoolean"));
	}

	protected PublicClaimBoolean(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject publicClaimBooleanMendixObject)
	{
		super(context, publicClaimBooleanMendixObject);
		if (!com.mendix.core.Core.isSubClassOf("JWT.PublicClaimBoolean", publicClaimBooleanMendixObject.getType()))
			throw new java.lang.IllegalArgumentException("The given object is not a JWT.PublicClaimBoolean");
	}

	/**
	 * @deprecated Use 'PublicClaimBoolean.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static jwt.proxies.PublicClaimBoolean initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return jwt.proxies.PublicClaimBoolean.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 */
	public static jwt.proxies.PublicClaimBoolean initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new jwt.proxies.PublicClaimBoolean(context, mendixObject);
	}

	public static jwt.proxies.PublicClaimBoolean load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return jwt.proxies.PublicClaimBoolean.initialize(context, mendixObject);
	}

	/**
	 * @return value of Value
	 */
	public final java.lang.Boolean getValue()
	{
		return getValue(getContext());
	}

	/**
	 * @param context
	 * @return value of Value
	 */
	public final java.lang.Boolean getValue(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Boolean) getMendixObject().getValue(context, MemberNames.Value.toString());
	}

	/**
	 * Set value of Value
	 * @param value
	 */
	public final void setValue(java.lang.Boolean value)
	{
		setValue(getContext(), value);
	}

	/**
	 * Set value of Value
	 * @param context
	 * @param value
	 */
	public final void setValue(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Boolean value)
	{
		getMendixObject().setValue(context, MemberNames.Value.toString(), value);
	}

	@java.lang.Override
	public boolean equals(Object obj)
	{
		if (obj == this)
			return true;

		if (obj != null && getClass().equals(obj.getClass()))
		{
			final jwt.proxies.PublicClaimBoolean that = (jwt.proxies.PublicClaimBoolean) obj;
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
		return "JWT.PublicClaimBoolean";
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
