// This file was generated by Mendix Modeler.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package jwt.proxies;

public enum ENU_Algorithm
{
	HS256(new java.lang.String[][] { new java.lang.String[] { "en_US", "HS256" } }),
	HS384(new java.lang.String[][] { new java.lang.String[] { "en_US", "HS384" } }),
	HS512(new java.lang.String[][] { new java.lang.String[] { "en_US", "HS512" } }),
	RS256(new java.lang.String[][] { new java.lang.String[] { "en_US", "RS256" } }),
	RS384(new java.lang.String[][] { new java.lang.String[] { "en_US", "RS384" } }),
	RS512(new java.lang.String[][] { new java.lang.String[] { "en_US", "RS512" } });

	private java.util.Map<java.lang.String, java.lang.String> captions;

	private ENU_Algorithm(java.lang.String[][] captionStrings)
	{
		this.captions = new java.util.HashMap<java.lang.String, java.lang.String>();
		for (java.lang.String[] captionString : captionStrings)
			captions.put(captionString[0], captionString[1]);
	}

	public java.lang.String getCaption(java.lang.String languageCode)
	{
		if (captions.containsKey(languageCode))
			return captions.get(languageCode);
		return captions.get("en_US");
	}

	public java.lang.String getCaption()
	{
		return captions.get("en_US");
	}
}
