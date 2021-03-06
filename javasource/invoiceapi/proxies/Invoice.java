// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package invoiceapi.proxies;

public class Invoice
{
	private final com.mendix.systemwideinterfaces.core.IMendixObject invoiceMendixObject;

	private final com.mendix.systemwideinterfaces.core.IContext context;

	/**
	 * Internal name of this entity
	 */
	public static final java.lang.String entityName = "InvoiceAPI.Invoice";

	/**
	 * Enum describing members of this entity
	 */
	public enum MemberNames
	{
		InvoiceId("InvoiceId"),
		TotalAmount("TotalAmount"),
		InvoiceDate("InvoiceDate"),
		Invoice_Account("InvoiceAPI.Invoice_Account");

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

	public Invoice(com.mendix.systemwideinterfaces.core.IContext context)
	{
		this(context, com.mendix.core.Core.instantiate(context, "InvoiceAPI.Invoice"));
	}

	protected Invoice(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject invoiceMendixObject)
	{
		if (invoiceMendixObject == null)
			throw new java.lang.IllegalArgumentException("The given object cannot be null.");
		if (!com.mendix.core.Core.isSubClassOf("InvoiceAPI.Invoice", invoiceMendixObject.getType()))
			throw new java.lang.IllegalArgumentException("The given object is not a InvoiceAPI.Invoice");

		this.invoiceMendixObject = invoiceMendixObject;
		this.context = context;
	}

	/**
	 * @deprecated Use 'Invoice.load(IContext, IMendixIdentifier)' instead.
	 */
	@java.lang.Deprecated
	public static invoiceapi.proxies.Invoice initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		return invoiceapi.proxies.Invoice.load(context, mendixIdentifier);
	}

	/**
	 * Initialize a proxy using context (recommended). This context will be used for security checking when the get- and set-methods without context parameters are called.
	 * The get- and set-methods with context parameter should be used when for instance sudo access is necessary (IContext.createSudoClone() can be used to obtain sudo access).
	 */
	public static invoiceapi.proxies.Invoice initialize(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixObject mendixObject)
	{
		return new invoiceapi.proxies.Invoice(context, mendixObject);
	}

	public static invoiceapi.proxies.Invoice load(com.mendix.systemwideinterfaces.core.IContext context, com.mendix.systemwideinterfaces.core.IMendixIdentifier mendixIdentifier) throws com.mendix.core.CoreException
	{
		com.mendix.systemwideinterfaces.core.IMendixObject mendixObject = com.mendix.core.Core.retrieveId(context, mendixIdentifier);
		return invoiceapi.proxies.Invoice.initialize(context, mendixObject);
	}

	public static java.util.List<invoiceapi.proxies.Invoice> load(com.mendix.systemwideinterfaces.core.IContext context, java.lang.String xpathConstraint) throws com.mendix.core.CoreException
	{
		java.util.List<invoiceapi.proxies.Invoice> result = new java.util.ArrayList<invoiceapi.proxies.Invoice>();
		for (com.mendix.systemwideinterfaces.core.IMendixObject obj : com.mendix.core.Core.retrieveXPathQuery(context, "//InvoiceAPI.Invoice" + xpathConstraint))
			result.add(invoiceapi.proxies.Invoice.initialize(context, obj));
		return result;
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
	 * @return value of InvoiceId
	 */
	public final java.lang.Long getInvoiceId()
	{
		return getInvoiceId(getContext());
	}

	/**
	 * @param context
	 * @return value of InvoiceId
	 */
	public final java.lang.Long getInvoiceId(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Long) getMendixObject().getValue(context, MemberNames.InvoiceId.toString());
	}

	/**
	 * Set value of InvoiceId
	 * @param invoiceid
	 */
	public final void setInvoiceId(java.lang.Long invoiceid)
	{
		setInvoiceId(getContext(), invoiceid);
	}

	/**
	 * Set value of InvoiceId
	 * @param context
	 * @param invoiceid
	 */
	public final void setInvoiceId(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Long invoiceid)
	{
		getMendixObject().setValue(context, MemberNames.InvoiceId.toString(), invoiceid);
	}

	/**
	 * @return value of TotalAmount
	 */
	public final java.lang.Integer getTotalAmount()
	{
		return getTotalAmount(getContext());
	}

	/**
	 * @param context
	 * @return value of TotalAmount
	 */
	public final java.lang.Integer getTotalAmount(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.lang.Integer) getMendixObject().getValue(context, MemberNames.TotalAmount.toString());
	}

	/**
	 * Set value of TotalAmount
	 * @param totalamount
	 */
	public final void setTotalAmount(java.lang.Integer totalamount)
	{
		setTotalAmount(getContext(), totalamount);
	}

	/**
	 * Set value of TotalAmount
	 * @param context
	 * @param totalamount
	 */
	public final void setTotalAmount(com.mendix.systemwideinterfaces.core.IContext context, java.lang.Integer totalamount)
	{
		getMendixObject().setValue(context, MemberNames.TotalAmount.toString(), totalamount);
	}

	/**
	 * @return value of InvoiceDate
	 */
	public final java.util.Date getInvoiceDate()
	{
		return getInvoiceDate(getContext());
	}

	/**
	 * @param context
	 * @return value of InvoiceDate
	 */
	public final java.util.Date getInvoiceDate(com.mendix.systemwideinterfaces.core.IContext context)
	{
		return (java.util.Date) getMendixObject().getValue(context, MemberNames.InvoiceDate.toString());
	}

	/**
	 * Set value of InvoiceDate
	 * @param invoicedate
	 */
	public final void setInvoiceDate(java.util.Date invoicedate)
	{
		setInvoiceDate(getContext(), invoicedate);
	}

	/**
	 * Set value of InvoiceDate
	 * @param context
	 * @param invoicedate
	 */
	public final void setInvoiceDate(com.mendix.systemwideinterfaces.core.IContext context, java.util.Date invoicedate)
	{
		getMendixObject().setValue(context, MemberNames.InvoiceDate.toString(), invoicedate);
	}

	/**
	 * @return value of Invoice_Account
	 */
	public final administration.proxies.Account getInvoice_Account() throws com.mendix.core.CoreException
	{
		return getInvoice_Account(getContext());
	}

	/**
	 * @param context
	 * @return value of Invoice_Account
	 */
	public final administration.proxies.Account getInvoice_Account(com.mendix.systemwideinterfaces.core.IContext context) throws com.mendix.core.CoreException
	{
		administration.proxies.Account result = null;
		com.mendix.systemwideinterfaces.core.IMendixIdentifier identifier = getMendixObject().getValue(context, MemberNames.Invoice_Account.toString());
		if (identifier != null)
			result = administration.proxies.Account.load(context, identifier);
		return result;
	}

	/**
	 * Set value of Invoice_Account
	 * @param invoice_account
	 */
	public final void setInvoice_Account(administration.proxies.Account invoice_account)
	{
		setInvoice_Account(getContext(), invoice_account);
	}

	/**
	 * Set value of Invoice_Account
	 * @param context
	 * @param invoice_account
	 */
	public final void setInvoice_Account(com.mendix.systemwideinterfaces.core.IContext context, administration.proxies.Account invoice_account)
	{
		if (invoice_account == null)
			getMendixObject().setValue(context, MemberNames.Invoice_Account.toString(), null);
		else
			getMendixObject().setValue(context, MemberNames.Invoice_Account.toString(), invoice_account.getMendixObject().getId());
	}

	/**
	 * @return the IMendixObject instance of this proxy for use in the Core interface.
	 */
	public final com.mendix.systemwideinterfaces.core.IMendixObject getMendixObject()
	{
		return invoiceMendixObject;
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
			final invoiceapi.proxies.Invoice that = (invoiceapi.proxies.Invoice) obj;
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
		return "InvoiceAPI.Invoice";
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
