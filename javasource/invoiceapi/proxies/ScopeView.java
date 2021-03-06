// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package invoiceapi.proxies;

public class ScopeView
{
	private final com.mendix.systemwideinterfaces.core.IMendixObject scopeViewMendixObject;

	private final com.mendix.systemwideinterfaces.core.IContext context;

	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "InvoiceAPI.ScopeView";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		Scope("Scope");

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

	public ScopeView(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, "InvoiceAPI.ScopeView"));
	}

	protected ScopeView(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject scopeViewMendixObject)
	{
		if (scopeViewMendixObject == null)
			throw new java.lang.IllegalArgumentException("The given object cannot be null.");
		if (!com.mendix.core.Core.isSubClassOf("InvoiceAPI.ScopeView", scopeViewMendixObject.getType()))
			throw new java.lang.IllegalArgumentException("The given object is not a InvoiceAPI.ScopeView");

		this.scopeViewMendixObject = scopeViewMendixObject;
		this.context = context;
	}

	/**
	 * @deprecated Use 'ScopeView.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static invoiceapi.proxies.ScopeView initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return invoiceapi.proxies.ScopeView.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 */
	public static invoiceapi.proxies.ScopeView initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new invoiceapi.proxies.ScopeView(context, mendixObject);
	}

	public static invoiceapi.proxies.ScopeView load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return invoiceapi.proxies.ScopeView.initialize(context, mendixObject);
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
	 * @return value of Scope
	 */
	public final java.lang.String getScope()
	{
		return getScope(getContext());
	}

	/**
	 * @param context
	 * @return value of Scope
	 */
	public final java.lang.String getScope(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.String) getMendixObject().getValue(context, MemberNames.Scope.toString());
	}

	/**
	 * Set value of Scope
	 * @param scope
	 */
	public final void setScope(java.lang.String scope)
	{
		setScope(getContext(), scope);
	}

	/**
	 * Set value of Scope
	 * @param context
	 * @param scope
	 */
	public final void setScope(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String scope)
	{
		getMendixObject().setValue(context, MemberNames.Scope.toString(), scope);
	}

	/**
	 * @return the IMendixObject instance of this proxy for use in the Core interface.
	 */
	public final com.mendix.systemwideinterfaces.core.IMendixObject getMendixObject()
	{
		return scopeViewMendixObject;
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
			final invoiceapi.proxies.ScopeView that = (invoiceapi.proxies.ScopeView) obj;
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
		return "InvoiceAPI.ScopeView";
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
