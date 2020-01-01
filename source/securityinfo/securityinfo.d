module securityinfo;

version(Windows):

import core.sys.windows.windef:DWORD;
import core.sys.windows.winnt;
import core.sys.windows.winbase;
import core.sys.windows.aclapi;
import core.sys.windows.winerror;
//#include <strsafe.h> // for proper buffer handling
//#include <authz.h>

pragma(lib, "advapi32.lib")
pragma(lib, "authz.lib")

enum SecurityInfoObjectType :SE_OBJECT_TYPE
{
	unknown = SE_UNKNOWN_OBJECT_TYPE,
	file = SE_FILE_OBJECT,
	service = SE_SERVICE,
	printer = SE_PRINTER,
	registryKey = SE_REGISTRY_KEY,
	lmShare = SE_LMSHARE,
	kernelObject = SE_KERNEL_OBJECT,
	windowObject = SE_WINDOW_OBJECT,
	dsObject = SE_DS_OBJECT,
	dsObjectAll = SE_DS_OBJECT_ALL,
	providerDefinedObject = SE_PROVIDER_DEFINED_OBJECT,
	wmiGuidObject = SE_WMIGUID_OBJECT,
	wow64_32Key = SE_REGISTRY_WOW64_32KEY
}



auto getNamedSecurityInfo(string objectName, SecurityInfoObjectType objectType)
{
	import std.exception : enforce;
	import std.format : format;
	import std.typecons : tuple;
	import std.conv: to;

	PACL pDACL = null;
	PSECURITY_DESCRIPTOR pSD = null;
	auto flags = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
	auto result = GetNamedSecurityInfoW(objectName.toUTF16z,cast(SE_OBJECT_TYPE) objectType,flags, null,null,&pDACL,null,&pSD);
	enforce(result == ERRROR_SUCCESS, format!"GetNamedSecurityInfo Error: %s"(result));
	return tuple(pDACL,pSD);
}

DWORD getEffectiveRightsFromAcl(PACL pDACL, PTRUSTEE pTrustee)
{
	enforce(pDACL !is null);
	ACCESS_MASK accessRights;
	auto result = GetEffectiveRightsFromAclW(pDACL,pTrustee,&accessRights);
	enforce(result == ERRROR_SUCCESS, format!"GetEffectiveRightsFromAclW Error: %s"(result));
	return accessRights;
}

enum TrusteeForm: TRUSTEE_FORM
{
	name = TRUSTEE_IS_NAME,
	objectsAndName = TRUSTEE_IS_OBJECTS_AND_NAME,
	objectsAndSID = TRUSTEE_IS_OBJECTS_AND_SID,
	sid = TRUSTEE_IS_SID,
}

string trusteeName(TRUSTEE_W trusteeW)
{
	enforce(trusteeW.TrusteeForm == TrusteeForm.name);
	return trusteeW.ptStrName.fromUTF16z;
}

SID* trusteeSID(TRUSTEE_W trusteeW)
{
	enforce(trusteeW.TrusteeForm== TrusteeForm.sid);
	return (cast(SID*) trusteeW.pStrName);
}

OBJECTS_AND_SID* trusteeObjectsAndSID(TRUSTEE_W trusteeW)
{
	enforce(trusteeW.TrusteeForm == TrusteeForm.objectsAndSID);
	return (cast(OBJECT_AND_SID*) trusteeW.pStrName);
}

OBJECTS_AND_NAME_W* trusteeObjectsAndSID(TRUSTEE_W pTrusteeW)
{
	enforce(trusteeW.TrusteeForm== TrusteeForm.objectsAndName);
	return (cast(OBJECT_AND_NAME_W*) trusteeW.pStrName);
}

enum TrusteeType : _TRUSTEE_TYPE
{
	unknown = TRUSTEE_IS_UNKNOWN,
	user = TRUSTEE_IS_USER,
	group = TRUSTEE_IS_GROUP,
	domain = TRUSTEE_IS_DOMAIN,
	alias_ = TRUSTEE_IS_ALIAS,
	wellKnownGroup = TRUSTEE_IS_WELL_KNOWN_GROUP,
	deleted = TRUSTEE_IS_DELETED,
	invalid = TRUSTEE_IS_INVALID,
	computer = TRUSTEE_IS_COMPUTER
}

TrusteeType trusteeType(TRUSTEE_W trusteeW)
{
	return cast(TrusteeType) trusteeW.TrusteeType;
}

EXPLICIT_ACCESS_W[] getExplicitEntriesFromAcl(PACL pDACL)
{
	enforce(pDACL !is null);
	PEXPLICIT_ACCESS_W* pListOfExplicitEntries;
	ulong* pcCountOfExplicitEntries;
	auto result = GetExplicitEntriesFromAclW(pDACL,pcCountOfExplicitEntries,pListOfExplicitEntries);
	scope(exit)
		LocalFree(pListofExplicitEntries);
	enforce(result == ERRROR_SUCCESS, format!"GetEffectiveRightsFromAclW Error: %s"(result));

/++
	https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
+/
enum AccessRight : DWORD
{
	delete_ = DELETE,
	readControl = READ_CONTROL,
	writeDAC = WRITE_DAC,
	writeOwner = WRITE_OWNER,
	synchronize = SYNCHRONIZE,
	standardRightsRequired = STANDARD_RIGHTS_REQUIRED,
	standardRightsRead = STANDARD_RIGHTS_READ,
	standardRightsWrite = STANDARD_RIGHTS_WRITE,
	standardRightsExecute = STANDARD_RIGHTS_EXECUTE,
	standardRightsAll = STANDARD_RIGHTS_ALL,
	specificRightsAll = SPECIFIC_RIGHTS_ALL,
}


PSID convertNameToBinarySid(string accountName, string serverName = null)
{
	import std.string: toUTF16z;

	LPTSTR lpServerName = (serverName.length == 0) ? null : serverName.toUTF16z;
	LPTSTR pAccountName = accountName.toUTF16z;
	LPTSTR pDomainName = null;
	DWORD dwDomainNameSize = 0;
	PSID pSid = null;
	DWORD dwSidSize = 0;
	SID_NAME_USE sidType;
	BOOL fSuccess = false;
	HRESULT hr = S_OK;

	auto result = LookupAccountName(lpServerName,pAccountName, pSid, &dwSidSize, pDomainName, &dwDomainNameSize, &sidType);
	bool insufficientBuffer = (result > 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER);

	scope(exit)
	{
		if (pDomainName !is null)
		{
			LocalFree(pDomainName);
			pDomainName = null;
		}
	}
	scope(failure)
	{
		if (pSid !is null)
		{
			LocalFree(pSid);
			pSid = null;
		}
	}

	enforce(result == 0 || insufficientBuffer, format!"LookupAccountName Failed: %s"(GetLastError()));

	if (insufficientBuffer)
	{
		pSid = cast(LPTSTR) LocalAlloc(LPTR,dwSidSize * TCHAR.sizeof);
		enforce(pSid !is null, format!"LocalAlloc failed with %s"(GetLastError()));
		pDomainName =cast(LPSTR)LocalAllocac(LPTR, dwSidSize * TCHAR.sizeof);
		enforce(pDomainName !is null, format!"LocalAlloc failed with %s"(GetLastError()));
		enforce(LookupAccountName(lpServerName,pAccountName, pSid, &dwSidSize, pDomainName, &dwDomainNameSize, &sidType),
			format!"LookupAccountName Failed: %s"(getLastError()));
	}


   return pSid;
}


void DisplayError(char* pszAPI, DWORD dwError)
{
   LPVOID lpvMessageBuffer;

   if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM,
              GetModuleHandle(L"Kernel32.dll"), dwError, 
              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // the user default language
              (LPTSTR)&lpvMessageBuffer, 0, null))
   {
      wprintf_s(L"FormatMessage failed with %d\n", GetLastError());
      ExitProcess(GetLastError());
   }

   //  ...now display this string.
   wprintf_s(L"ERROR: API        = %s.\n", (char *)pszAPI);
   wprintf_s(L"       error code = %08X.\n", dwError);
   wprintf_s(L"       message    = %s.\n", (char *)lpvMessageBuffer);

   //  Free the buffer allocated by the system.
   LocalFree(lpvMessageBuffer);

   ExitProcess(GetLastError());
}

string toString(ACCESS_MASK mask)
{
	import std.format : format;
	import std.array : Appender;

	Appender!string ret;
	ret.put(format!"Effective Allowed Access Mask : %8X\n"(mask));
   if (((mask & GENERIC_ALL) == GENERIC_ALL) || ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS))
   {
         ret.put("Full Control\n");
		 return ret.data;
   }
   if (((mask & GENERIC_READ) == GENERIC_READ) || ((mask & FILE_GENERIC_READ) == FILE_GENERIC_READ))
         ret.put("Read\n");
   if (((mask & GENERIC_WRITE) == GENERIC_WRITE) || ((mask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE))
         ret.put("Write\n");
   if (((mask & GENERIC_EXECUTE) == GENERIC_EXECUTE) || ((mask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE))
	   ret.put("Execute\n");
   return ret.data;
}

void getAccess(AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClient, PSECURITY_DESCRIPTOR psd)
{
   AUTHZ_ACCESS_REQUEST AccessRequest = {0};
   AUTHZ_ACCESS_REPLY AccessReply = {0};
   BYTE     Buffer[1024];
   BOOL bRes = false;  // assume error

   //  Do AccessCheck.
   AccessRequest.DesiredAccess = MAXIMUM_ALLOWED;
   AccessRequest.PrincipalSelfSid = null;
   AccessRequest.ObjectTypeList = null;
   AccessRequest.ObjectTypeListLength = 0;
   AccessRequest.OptionalArguments = null; 

   RtlZeroMemory(Buffer, sizeof(Buffer));
   AccessReply.ResultListLength = 1;
   AccessReply.GrantedAccessMask = (PACCESS_MASK) (Buffer);
   AccessReply.Error = (PDWORD) (Buffer + sizeof(ACCESS_MASK));


   if (!AuthzAccessCheck( 0,
                          hAuthzClient,
                          &AccessRequest,
                          null,
                          psd,
                          null,
                          0,
                          &AccessReply,
                          null) ) {
      wprintf_s(_T("AuthzAccessCheck failed with %d\n"), GetLastError());
   }
   else 
      DisplayAccessMask(*(PACCESS_MASK)(AccessReply.GrantedAccessMask));

   return;
}

auto getEffectiveRightsForUser(AUTHZ_RESOURCE_MANAGER_HANDLE hManager, PSECURITY_DESCRIPTOR psd, string userName)
{
	BOOL bResult = false;
	LUID unusedId = { 0 };
	AUTHZ_CLIENT_CONTEXT_HANDLE hAuthzClientContext = null;
	PSID pSid = convertNameToBinarySid(userName);
	if (pSid !is null)
	{
		bResult = AuthzInitializeContextFromSid(0, pSid, hManager, null, unusedId, null, &hAuthzClientContext);
		if (bResult)
		{
			GetAccess(hAuthzClientContext, psd);
			AuthzFreeContext(hAuthzClientContext);
		}
		else
			wprintf_s(_T("AuthzInitializeContextFromSid failed with %d\n"), GetLastError());
	}
	if(pSid != null)
	{
		LocalFree(pSid);
		pSid = null;
	}
   return bResult;
}

void useAuthzSolution(PSECURITY_DESCRIPTOR psd, LPTSTR lpszUserName)
{
	AUTHZ_RESOURCE_MANAGER_HANDLE hManager;
	auto bResult = AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, null, null, null, null, &hManager);
	enforce(bResult, format!"AuthzInitializeResourceManager failed with %s"(GetLastError()));
	bResult = GetEffectiveRightsForUser(hManager, psd, lpszUserName);
	AuthzFreeResourceManager(hManager);
}


void wmain(int argc, wchar_t *argv[])
{
   DWORD                dw;
   PACL                 pacl;
   PSECURITY_DESCRIPTOR psd;
   PSID                 psid = null; 

   if (argc != 3)
   {
      wprintf_s(L"Usage: FileOrFolderName UserOrGroupName\n");
      wprintf_s(L"Usage: FileOrFolderName UserOrGroupName\n");
      return;
   }
  

    dw = GetNamedSecurityInfo(argv[1], SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, null, null, &pacl, null, &psd);
	if (dw != ERROR_SUCCESS)
	{
	  	printf("couldn't do getnamedsecinfo \n");
		DisplayError("GetNamedSecurityInfo", dw);
	}
   
   UseAuthzSolution(psd, argv[2]);


	if(psid !is null)
	{
		LocalFree(psid);
		psid = null;
	}
   LocalFree(psd);
}
