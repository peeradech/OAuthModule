// This file was generated by Mendix Modeler 7.23.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package viewapp.proxies.microflows;

import java.util.HashMap;
import java.util.Map;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.systemwideinterfaces.MendixRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class Microflows
{
	// These are the microflows for the ViewApp module
	public static void aCT_OpenCreateInvoice(IContext context)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			Core.execute(context, "ViewApp.ACT_OpenCreateInvoice", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void aCT_SaveInvoice(IContext context, viewapp.proxies.InvoiceView _invoiceView)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("InvoiceView", _invoiceView == null ? null : _invoiceView.getMendixObject());
			Core.execute(context, "ViewApp.ACT_SaveInvoice", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static java.util.List<viewapp.proxies.InvoiceView> dSL_GetInvoices(IContext context)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			java.util.List<IMendixObject> objs = Core.execute(context, "ViewApp.DSL_GetInvoices", params);
			java.util.List<viewapp.proxies.InvoiceView> result = null;
			if (objs != null)
			{
				result = new java.util.ArrayList<viewapp.proxies.InvoiceView>();
				for (IMendixObject obj : objs)
					result.add(viewapp.proxies.InvoiceView.initialize(context, obj));
			}
			return result;
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
}