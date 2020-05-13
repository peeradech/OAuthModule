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
 * Secure one-way hash functions that takes arbitrary-sized data and output a fixed-length hash value using the SHA-256 hash algorithm. 
 * 
 * - value : the value to hash
 * - length : the desired length of the hash. 
 * 
 * Returns a SHA-256 hash of 'value', with length 'length'
 */
public class Hash extends CustomJavaAction<java.lang.String>
{
	private java.lang.String value;
	private java.lang.Long length;

	public Hash(IContext context, java.lang.String value, java.lang.Long length)
	{
		super(context);
		this.value = value;
		this.length = length;
	}

	@java.lang.Override
	public java.lang.String executeAction() throws Exception
	{
		// BEGIN USER CODE
		return StringUtils.hash(value, length.intValue());
		// END USER CODE
	}

	/**
	 * Returns a string representation of this action
	 */
	@java.lang.Override
	public java.lang.String toString()
	{
		return "Hash";
	}

	// BEGIN EXTRA CODE
	// END EXTRA CODE
}
