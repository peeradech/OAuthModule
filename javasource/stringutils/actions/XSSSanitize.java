// This file was generated by Mendix Modeler.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
// Special characters, e.g., é, ö, à, etc. are supported in comments.

package stringutils.actions;

import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.webui.CustomJavaAction;
import stringutils.StringUtils;

/**
 * Removes all potiential dangerous HTML from a string so that it can be safely displayed in a browser. 
 * 
 * This function should be applied to all HTML which is displayed in the browser and is be submitted by (untrusted) users.
 * 
 * - HTML: The html to sanitize
 * - policy: The policy that defines the allowed HTML tags a user is allowd to use:
 * 
 * Sanitize policies as described by OWASP.
 * 'eBay':
 * * eBay (http://www.ebay.com/) is the most popular online auction site in the
 *  * universe, as far as I can tell. It is a public site so anyone is allowed to
 *  * post listings with rich HTML content. It's not surprising that given the
 *  * attractiveness of eBay as a target that it has been subject to a few complex
 *  * XSS attacks. Listings are allowed to contain much more rich content than,
 *  * say, Slashdot- so it's attack surface is considerably larger.
 * 
 * 'Slashdot':
 *  * Slashdot (http://www.slashdot.org/) is a techie news site that allows users
 *  * to respond anonymously to news posts with very limited HTML markup. Now
 *  * Slashdot is not only one of the coolest sites around, it's also one that's
 *  * been subject to many different successful attacks. 
 *  * The rules for Slashdot are fairly strict: users
 *  * can only submit the following HTML tags and no CSS: {<b>}, {<u>},
 *  * {<i>}, {<a>}, {<blockquote>}.
 */
public class XSSSanitize extends CustomJavaAction<java.lang.String>
{
	private java.lang.String html;
	private stringutils.proxies.XSSPolicy policy;

	public XSSSanitize(IContext context, java.lang.String html, java.lang.String policy)
	{
		super(context);
		this.html = html;
		this.policy = policy == null ? null : stringutils.proxies.XSSPolicy.valueOf(policy);
	}

	@java.lang.Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		return StringUtils.XSSSanitize(html, policy);
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "XSSSanitize";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
