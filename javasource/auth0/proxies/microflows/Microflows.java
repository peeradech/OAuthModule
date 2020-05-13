// This file was generated by Mendix Modeler 7.23.
//
// WARNING: Code you write here will be lost the next time you deploy the project.

package auth0.proxies.microflows;

import java.util.HashMap;
import java.util.Map;
import com.mendix.core.Core;
import com.mendix.core.CoreException;
import com.mendix.systemwideinterfaces.MendixRuntimeException;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.IMendixObject;

public class Microflows
{
	// These are the microflows for the Auth0 module
	public static void aCT_ConvertPEMToDER(IContext context, auth0.proxies.PEMKey _pEMKey)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("PEMKey", _pEMKey == null ? null : _pEMKey.getMendixObject());
			Core.execute(context, "Auth0.ACT_ConvertPEMToDER", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static auth0.proxies.LogoutHelper dSS_GetLogoutHelper(IContext context)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			IMendixObject result = (IMendixObject)Core.execute(context, "Auth0.DSS_GetLogoutHelper", params);
			return result == null ? null : auth0.proxies.LogoutHelper.initialize(context, result);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static jwt.proxies.JWT iVK_DecodeAndValidateJWT(IContext context, jwt.proxies.JWTRSAPublicKey _jWTRSAPublicKey, auth0.proxies.Token _token)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("JWTRSAPublicKey", _jWTRSAPublicKey == null ? null : _jWTRSAPublicKey.getMendixObject());
			params.put("Token", _token == null ? null : _token.getMendixObject());
			IMendixObject result = (IMendixObject)Core.execute(context, "Auth0.IVK_DecodeAndValidateJWT", params);
			return result == null ? null : jwt.proxies.JWT.initialize(context, result);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static system.proxies.User iVK_FindUserFromJWT(IContext context, jwt.proxies.JWT _jWT)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("JWT", _jWT == null ? null : _jWT.getMendixObject());
			IMendixObject result = (IMendixObject)Core.execute(context, "Auth0.IVK_FindUserFromJWT", params);
			return result == null ? null : system.proxies.User.initialize(context, result);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static system.proxies.FileDocument iVK_ImportPublicKey(IContext context, java.lang.String _keyId)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("KeyId", _keyId);
			IMendixObject result = (IMendixObject)Core.execute(context, "Auth0.IVK_ImportPublicKey", params);
			return result == null ? null : system.proxies.FileDocument.initialize(context, result);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void iVK_Redirect(IContext context, system.proxies.HttpResponse _httpResponse, java.lang.String _location)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("httpResponse", _httpResponse == null ? null : _httpResponse.getMendixObject());
			params.put("Location", _location);
			Core.execute(context, "Auth0.IVK_Redirect", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static jwt.proxies.JWTRSAPublicKey iVK_RetrievePublicKey(IContext context, auth0.proxies.Token _token)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("Token", _token == null ? null : _token.getMendixObject());
			IMendixObject result = (IMendixObject)Core.execute(context, "Auth0.IVK_RetrievePublicKey", params);
			return result == null ? null : jwt.proxies.JWTRSAPublicKey.initialize(context, result);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void iVK_StoreAccessToken(IContext context, auth0.proxies.Token _token, system.proxies.User _user)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("Token", _token == null ? null : _token.getMendixObject());
			params.put("User", _user == null ? null : _user.getMendixObject());
			Core.execute(context, "Auth0.IVK_StoreAccessToken", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void wOP_HandleCallback(IContext context, system.proxies.HttpRequest _httpRequest, system.proxies.HttpResponse _httpResponse, java.lang.String _code, java.lang.String _state)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("httpRequest", _httpRequest == null ? null : _httpRequest.getMendixObject());
			params.put("httpResponse", _httpResponse == null ? null : _httpResponse.getMendixObject());
			params.put("code", _code);
			params.put("state", _state);
			Core.execute(context, "Auth0.WOP_HandleCallback", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void wOP_HandleCallback_Line(IContext context, system.proxies.HttpRequest _httpRequest, system.proxies.HttpResponse _httpResponse, java.lang.String _code, java.lang.String _state)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("httpRequest", _httpRequest == null ? null : _httpRequest.getMendixObject());
			params.put("httpResponse", _httpResponse == null ? null : _httpResponse.getMendixObject());
			params.put("code", _code);
			params.put("state", _state);
			Core.execute(context, "Auth0.WOP_HandleCallback_Line", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void wOP_OpenUniversalLogin(IContext context, system.proxies.HttpRequest _httpRequest, system.proxies.HttpResponse _httpResponse)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("httpRequest", _httpRequest == null ? null : _httpRequest.getMendixObject());
			params.put("httpResponse", _httpResponse == null ? null : _httpResponse.getMendixObject());
			Core.execute(context, "Auth0.WOP_OpenUniversalLogin", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
	public static void wOP_OpenUniversalLogin_Line(IContext context, system.proxies.HttpRequest _httpRequest, system.proxies.HttpResponse _httpResponse)
	{
		try
		{
			Map<java.lang.String, Object> params = new HashMap<java.lang.String, Object>();
			params.put("httpRequest", _httpRequest == null ? null : _httpRequest.getMendixObject());
			params.put("httpResponse", _httpResponse == null ? null : _httpResponse.getMendixObject());
			Core.execute(context, "Auth0.WOP_OpenUniversalLogin_Line", params);
		}
		catch (CoreException e)
		{
			throw new MendixRuntimeException(e);
		}
	}
}