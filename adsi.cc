#define _CRT_SECURE_NO_WARNINGS

// MinGW compatibility fix - more targeted approach
#ifdef __MINGW32__
#include <stdio.h>
#include <stdarg.h>

#define INITGUID

// Only define if not already defined
#ifndef sprintf_s
inline int sprintf_s(char* buffer, size_t sizeOfBuffer, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeOfBuffer, format, args);
    va_end(args);
    return result;
}
#endif

#ifndef swprintf_s
inline int swprintf_s(wchar_t* buffer, size_t sizeOfBuffer, const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    int result = vswprintf(buffer, sizeOfBuffer, format, args);
    va_end(args);
    return result;
}
#endif

#endif // __MINGW32__

#define _WIN32_DCOM
#include <tchar.h>
#include <winsock2.h>  // Must come BEFORE winldap.h
#include <windows.h>
#include <winbase.h>    // LogonUserW()
#include <objbase.h>    // Required for COM
#include <combaseapi.h> // Ensures COM support
#include <winldap.h>
#include <winber.h>    // Add this for ber_free
#include <initguid.h>
#include <iads.h>
#include <adshlp.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <activeds.h>
#include <comdef.h>
#include <winreg.h>
#include <codecvt>           // Required for string conversion
#include <securitybaseapi.h> // ImpersonateLoggedOnUser()

#pragma comment(lib, "Activeds.lib")
#pragma comment(lib, "ActiveDS.lib")
#pragma comment(lib, "Adsiid.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Kernel32.lib")

DEFINE_GUID(IID_IADs, 0xFD8256D0, 0xFD15, 0x11CE, 0xAB, 0xC4, 0x02, 0x60, 0x8C, 0x9E, 0x75, 0x53);
DEFINE_GUID(IID_IADsContainer,
0x001677D0, 0xFD16, 0x11CE, 0xAB, 0xC4, 0x02, 0x60, 0x8C, 0x9E, 0x75, 0x53);

// Link libraries: -ladsiid -lactiveds -lole32 -loleaut32 -luuid -ladvapi32 -lwldap32

// Helper function to convert wide string to multi-byte string
std::string WideToMultiByte(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

// Helper function to convert multi-byte string to wide string
std::wstring MultiByteToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

class CentralRegistryManager {
private:
    bool initialized;
    LDAP* ldapSession;
    std::string ldapServer;
    std::string baseDN;

public:
    CentralRegistryManager() : initialized(false), ldapSession(nullptr) {
        CoInitialize(NULL);
        initialized = true;
    }

    ~CentralRegistryManager() {
        if (ldapSession) {
            ldap_unbind(ldapSession);
        }
        CoUninitialize();
    }

    // Initialize LDAP connection
    HRESULT InitializeLDAPConnection(const std::wstring& server, const std::wstring& domain,
                                   const std::wstring& username = L"", const std::wstring& password = L"") {
        HRESULT hr = S_OK;
        
        try {
            // Convert server name to multi-byte
            ldapServer = WideToMultiByte(server);
            baseDN = WideToMultiByte(domain);
            
            std::wcout << L"Initializing LDAP connection to: " << server << std::endl;
            
            // Initialize LDAP session using ldap_init
            ldapSession = ldap_init(const_cast<char*>(ldapServer.c_str()), LDAP_PORT);
            
            if (!ldapSession) {
                std::wcout << L"Failed to initialize LDAP session" << std::endl;
                return E_FAIL;
            }
            
            // Set LDAP version to 3
            ULONG version = LDAP_VERSION3;
            int result = ldap_set_option(ldapSession, LDAP_OPT_PROTOCOL_VERSION, &version);
            
            if (result != LDAP_SUCCESS) {
                std::wcout << L"Failed to set LDAP version: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
            // Set timeout
            LDAP_TIMEVAL timeout = {30, 0}; // 30 seconds
            ldap_set_option(ldapSession, LDAP_OPT_TIMELIMIT, &timeout);
            
            // Bind to LDAP server using ldap_bind_s
            if (!username.empty() && !password.empty()) {
                std::string userStr = WideToMultiByte(username);
                std::string passStr = WideToMultiByte(password);
                
                result = ldap_bind_s(ldapSession, 
                                   const_cast<char*>(userStr.c_str()),
                                   const_cast<char*>(passStr.c_str()),
                                   LDAP_AUTH_SIMPLE);
            } else {
                // Anonymous bind
                result = ldap_bind_s(ldapSession, nullptr, nullptr, LDAP_AUTH_SIMPLE);
            }
            
            if (result != LDAP_SUCCESS) {
                std::wcout << L"LDAP bind failed: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
            std::wcout << L"LDAP connection established successfully" << std::endl;
            
        } catch (...) {
            std::wcout << L"Exception during LDAP initialization" << std::endl;
            hr = E_FAIL;
        }
        
        return hr;
    }

    // Create Group Policy Object using both ADSI and LDAP
    HRESULT CreateRegistryGPO(const std::wstring& domainDN, const std::wstring& gpoName, std::wstring& outGpoGuid) {
        HRESULT hr = S_OK;
        IADsContainer* pPoliciesContainer = nullptr;
        IDispatch* pNewGPO = nullptr;
        IADs* pGPOObject = nullptr;

        try {
            // Connect to Policies container using ADsGetObject
            std::wstring policiesPath = L"LDAP://CN=Policies,CN=System," + domainDN;
            hr = ADsGetObject(policiesPath.c_str(), IID_IADsContainer, (void**)&pPoliciesContainer);
            
            if (FAILED(hr)) {
                std::wcout << L"Failed to connect to Policies container: " << std::hex << hr << std::endl;
                return hr;
            }

            // Generate GUID for new GPO
            GUID guid;
            CoCreateGuid(&guid);
            
            WCHAR szGuid[40];
            StringFromGUID2(guid, szGuid, 40);
            
            std::wstring gpoGuid = szGuid;
            outGpoGuid = gpoGuid;
            std::wstring gpoCN = L"CN=" + gpoGuid;

            // Create new GPO using IADsContainer::Create
            BSTR bstrClass = SysAllocString(L"groupPolicyContainer");
            BSTR bstrName = SysAllocString(gpoCN.c_str());
            
            hr = pPoliciesContainer->Create(bstrClass, bstrName, &pNewGPO);
            
            if (SUCCEEDED(hr)) {
                // Get IADs interface
                hr = pNewGPO->QueryInterface(IID_IADs, (void**)&pGPOObject);
                
                if (SUCCEEDED(hr)) {
                    // Set GPO properties using IADs::Put
                    VARIANT var;
                    VariantInit(&var);
                    
                    // Set display name
                    var.vt = VT_BSTR;
                    var.bstrVal = SysAllocString(gpoName.c_str());
                    hr = pGPOObject->Put(L"displayName", var);
                    VariantClear(&var);
                    
                    // Set flags for computer and user configuration
                    var.vt = VT_I4;
                    var.lVal = 0; // Enable both computer and user configuration
                    hr = pGPOObject->Put(L"flags", var);
                    VariantClear(&var);
                    
                    // Set version number
                    var.vt = VT_I4;
                    var.lVal = 1;
                    hr = pGPOObject->Put(L"versionNumber", var);
                    VariantClear(&var);
                    
                    // Commit changes using IADs::SetInfo
                    hr = pGPOObject->SetInfo();
                    
                    if (SUCCEEDED(hr)) {
                        std::wcout << L"Successfully created GPO: " << gpoName << L" with GUID: " << gpoGuid << std::endl;
                        
                        // Now use LDAP to add additional attributes
                        hr = EnhanceGPOWithLDAP(gpoGuid, domainDN);
                    }
                }
            }

            SysFreeString(bstrClass);
            SysFreeString(bstrName);
            
        } catch (_com_error& e) {
            std::wcout << L"Error creating GPO: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }

        if (pGPOObject) pGPOObject->Release();
        if (pNewGPO) pNewGPO->Release();
        if (pPoliciesContainer) pPoliciesContainer->Release();
        
        return hr;
    }

    // Enhance GPO with additional attributes using LDAP modify
    HRESULT EnhanceGPOWithLDAP(const std::wstring& gpoGuid, const std::wstring& domainDN) {
        if (!ldapSession) {
            std::wcout << L"LDAP session not initialized" << std::endl;
            return E_FAIL;
        }

        try {
            // Construct DN for the GPO
            std::string gpoDN = "CN=" + WideToMultiByte(gpoGuid) + ",CN=Policies,CN=System," + WideToMultiByte(domainDN);
            
            std::wcout << L"Enhancing GPO with LDAP modifications: " << MultiByteToWide(gpoDN) << std::endl;
            
            // Prepare LDAP modifications using ldap_modify_s
            LDAPMod* mods[4];
            LDAPMod mod1, mod2, mod3;
            
            // Add custom attribute for registry management
            char* descValues[] = {"Central Registry Management GPO", nullptr};
            mod1.mod_op = LDAP_MOD_REPLACE;
            mod1.mod_type = "description";
            mod1.mod_vals.modv_strvals = descValues;
            mods[0] = &mod1;
            
            // Add creation timestamp
            SYSTEMTIME st;
            GetSystemTime(&st);
            char timestamp[64];
            sprintf_s(timestamp, sizeof(timestamp), "%04d%02d%02d%02d%02d%02d.0Z", 
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            
            char* timeValues[] = {timestamp, nullptr};
            mod2.mod_op = LDAP_MOD_REPLACE;
            mod2.mod_type = "whenCreated";
            mod2.mod_vals.modv_strvals = timeValues;
            mods[1] = &mod2;
            
            // Add custom registry flag
            char* flagValues[] = {"REGISTRY_POLICY", nullptr};
            mod3.mod_op = LDAP_MOD_ADD;
            mod3.mod_type = "keywords";
            mod3.mod_vals.modv_strvals = flagValues;
            mods[2] = &mod3;
            
            mods[3] = nullptr; // Terminate array
            
            // Perform LDAP modify using ldap_modify_s
            int result = ldap_modify_s(ldapSession, const_cast<char*>(gpoDN.c_str()), mods);
            
            if (result == LDAP_SUCCESS) {
                std::wcout << L"LDAP modifications applied successfully" << std::endl;
            } else {
                std::wcout << L"LDAP modify failed: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
        } catch (...) {
            std::wcout << L"Exception during LDAP modification" << std::endl;
            return E_FAIL;
        }
        
        return S_OK;
    }

    // Search for GPOs using LDAP search
    HRESULT SearchGPOsWithLDAP(const std::wstring& domainDN, const std::wstring& filter = L"") {
        if (!ldapSession) {
            std::wcout << L"LDAP session not initialized" << std::endl;
            return E_FAIL;
        }

        try {
            // Construct search base
            std::string searchBase = "CN=Policies,CN=System," + WideToMultiByte(domainDN);
            
            // Construct search filter
            std::string searchFilter = "(objectClass=groupPolicyContainer)";
            if (!filter.empty()) {
                searchFilter = WideToMultiByte(filter);
            }
            
            std::wcout << L"Searching GPOs with LDAP..." << std::endl;
            std::wcout << L"Search Base: " << MultiByteToWide(searchBase) << std::endl;
            std::wcout << L"Filter: " << MultiByteToWide(searchFilter) << std::endl;
            
            // Attributes to retrieve
            char* attrs[] = {"cn", "displayName", "flags", "versionNumber", "whenCreated", "description", nullptr};
            
            LDAPMessage* searchResult = nullptr;
            
            // Perform LDAP search using ldap_search_s
            int result = ldap_search_s(ldapSession,
                                     const_cast<char*>(searchBase.c_str()),
                                     LDAP_SCOPE_ONELEVEL,
                                     const_cast<char*>(searchFilter.c_str()),
                                     attrs,
                                     0, // Return both attribute types and values
                                     &searchResult);
            
            if (result != LDAP_SUCCESS) {
                std::wcout << L"LDAP search failed: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
            // Process search results
            int entryCount = ldap_count_entries(ldapSession, searchResult);
            std::wcout << L"Found " << entryCount << L" GPO(s)" << std::endl;
            std::wcout << L"=== LDAP Search Results ===" << std::endl;
            
            LDAPMessage* entry = ldap_first_entry(ldapSession, searchResult);
            while (entry) {
                // Get DN
                char* dn = ldap_get_dn(ldapSession, entry);
                if (dn) {
                    std::wcout << L"DN: " << MultiByteToWide(dn) << std::endl;
                    ldap_memfree(dn);
                }
                
                // Get attributes
                BerElement* ber = nullptr;
                char* attr = ldap_first_attribute(ldapSession, entry, &ber);
                
                while (attr) {
                    char** values = ldap_get_values(ldapSession, entry, attr);
                    if (values) {
                        std::wcout << L"  " << MultiByteToWide(attr) << L": ";
                        for (int i = 0; values[i]; i++) {
                            if (i > 0) std::wcout << L", ";
                            std::wcout << MultiByteToWide(values[i]);
                        }
                        std::wcout << std::endl;
                        ldap_value_free(values);
                    }
                    ldap_memfree(attr);
                    attr = ldap_next_attribute(ldapSession, entry, ber);
                }
                
                if (ber) ber_free(ber, 0);
                std::wcout << L"---" << std::endl;
                
                entry = ldap_next_entry(ldapSession, entry);
            }
            
            ldap_msgfree(searchResult);
            
        } catch (...) {
            std::wcout << L"Exception during LDAP search" << std::endl;
            return E_FAIL;
        }
        
        return S_OK;
    }

    // Modify GPO attributes using LDAP modify
    HRESULT ModifyGPOWithLDAP(const std::wstring& domainDN, const std::wstring& gpoGuid, 
                             const std::wstring& newDisplayName) {
        if (!ldapSession) {
            std::wcout << L"LDAP session not initialized" << std::endl;
            return E_FAIL;
        }

        try {
            // Construct DN for the GPO
            std::string gpoDN = "CN=" + WideToMultiByte(gpoGuid) + ",CN=Policies,CN=System," + WideToMultiByte(domainDN);
            
            std::wcout << L"Modifying GPO with LDAP: " << MultiByteToWide(gpoDN) << std::endl;
            
            // Prepare LDAP modifications
            LDAPMod* mods[3];
            LDAPMod mod1, mod2;
            
            // Modify display name
            std::string newNameStr = WideToMultiByte(newDisplayName);
            char* nameValues[] = {const_cast<char*>(newNameStr.c_str()), nullptr};
            mod1.mod_op = LDAP_MOD_REPLACE;
            mod1.mod_type = "displayName";
            mod1.mod_vals.modv_strvals = nameValues;
            mods[0] = &mod1;
            
            // Update modification timestamp
            SYSTEMTIME st;
            GetSystemTime(&st);
            char timestamp[64];
            sprintf_s(timestamp, sizeof(timestamp), "%04d%02d%02d%02d%02d%02d.0Z", 
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            
            char* timeValues[] = {timestamp, nullptr};
            mod2.mod_op = LDAP_MOD_REPLACE;
            mod2.mod_type = "whenChanged";
            mod2.mod_vals.modv_strvals = timeValues;
            mods[1] = &mod2;
            
            mods[2] = nullptr; // Terminate array
            
            // Perform LDAP modify
            int result = ldap_modify_s(ldapSession, const_cast<char*>(gpoDN.c_str()), mods);
            
            if (result == LDAP_SUCCESS) {
                std::wcout << L"GPO modified successfully via LDAP" << std::endl;
            } else {
                std::wcout << L"LDAP modify failed: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
        } catch (...) {
            std::wcout << L"Exception during LDAP modification" << std::endl;
            return E_FAIL;
        }
        
        return S_OK;
    }

    // Delete GPO using LDAP delete
    HRESULT DeleteGPOWithLDAP(const std::wstring& domainDN, const std::wstring& gpoGuid) {
        if (!ldapSession) {
            std::wcout << L"LDAP session not initialized" << std::endl;
            return E_FAIL;
        }

        try {
            // Construct DN for the GPO
            std::string gpoDN = "CN=" + WideToMultiByte(gpoGuid) + ",CN=Policies,CN=System," + WideToMultiByte(domainDN);
            
            std::wcout << L"Deleting GPO with LDAP: " << MultiByteToWide(gpoDN) << std::endl;
            
            // Perform LDAP delete using ldap_delete_s
            int result = ldap_delete_s(ldapSession, const_cast<char*>(gpoDN.c_str()));
            
            if (result == LDAP_SUCCESS) {
                std::wcout << L"GPO deleted successfully via LDAP" << std::endl;
            } else {
                std::wcout << L"LDAP delete failed: " << ldap_err2stringW(result) << std::endl;
                return E_FAIL;
            }
            
        } catch (...) {
            std::wcout << L"Exception during LDAP deletion" << std::endl;
            return E_FAIL;
        }
        
        return S_OK;
    }

    // Add Registry Policy to existing GPO (keeping existing ADSI functionality)
    HRESULT AddRegistryPolicyToGPO(const std::wstring& domainDN, 
                                  const std::wstring& gpoGuid,
                                  const std::wstring& registryPath,
                                  const std::wstring& valueName,
                                  const std::wstring& valueData,
                                  DWORD valueType) {
        HRESULT hr = S_OK;
        IADs* pGPO = nullptr;
        IADsContainer* pMachineContainer = nullptr;
        IDispatch* pRegistryContainer = nullptr;
        IADs* pRegistryObject = nullptr;

        try {
            // Connect to GPO using ADsGetObject
            std::wstring gpoPath = L"LDAP://CN=" + gpoGuid + L",CN=Policies,CN=System," + domainDN;
            hr = ADsGetObject(gpoPath.c_str(), IID_IADs, (void**)&pGPO);
            
            if (FAILED(hr)) {
                std::wcout << L"Failed to connect to GPO: " << std::hex << hr << std::endl;
                return hr;
            }

            // Get or create Machine container
            std::wstring machineContainerPath = gpoPath + L",CN=Machine";
            hr = ADsGetObject(machineContainerPath.c_str(), IID_IADsContainer, (void**)&pMachineContainer);
            
            if (FAILED(hr)) {
                // Create Machine container if it doesn't exist
                hr = CreateGPOSubContainer(pGPO, L"Machine");
                if (FAILED(hr)) return hr;
                
                hr = ADsGetObject(machineContainerPath.c_str(), IID_IADsContainer, (void**)&pMachineContainer);
            }

            if (SUCCEEDED(hr)) {
                // Create registry policy container
                std::wstring registryContainerName = L"CN=Registry";
                
                BSTR bstrClass = SysAllocString(L"container");
                BSTR bstrName = SysAllocString(registryContainerName.c_str());
                
                hr = pMachineContainer->Create(bstrClass, bstrName, &pRegistryContainer);
                
                if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
                    // Get the registry container
                    std::wstring regContainerPath = machineContainerPath + L"," + registryContainerName;
                    
                    IADs* pRegContainer = nullptr;
                    hr = ADsGetObject(regContainerPath.c_str(), IID_IADs, (void**)&pRegContainer);
                    
                    if (SUCCEEDED(hr)) {
                        // Create registry entry
                        hr = CreateRegistryEntry(pRegContainer, registryPath, valueName, valueData, valueType);
                        
                        // Also update using LDAP for additional tracking
                        if (SUCCEEDED(hr)) {
                            UpdateRegistryEntryWithLDAP(gpoGuid, domainDN, registryPath, valueName);
                        }
                        
                        pRegContainer->Release();
                    }
                }
                
                SysFreeString(bstrClass);
                SysFreeString(bstrName);
            }

        } catch (_com_error& e) {
            std::wcout << L"Error adding registry policy: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }

        if (pRegistryObject) pRegistryObject->Release();
        if (pRegistryContainer) pRegistryContainer->Release();
        if (pMachineContainer) pMachineContainer->Release();
        if (pGPO) pGPO->Release();
        
        return hr;
    }

    // Update registry entry tracking with LDAP
    HRESULT UpdateRegistryEntryWithLDAP(const std::wstring& gpoGuid, const std::wstring& domainDN,
                                       const std::wstring& registryPath, const std::wstring& valueName) {
        if (!ldapSession) return S_OK; // Skip if LDAP not available
        
        try {
            // Construct DN for the GPO
            std::string gpoDN = "CN=" + WideToMultiByte(gpoGuid) + ",CN=Policies,CN=System," + WideToMultiByte(domainDN);
            
            // Add registry path to keywords for tracking
            std::string regInfo = WideToMultiByte(registryPath + L"\\" + valueName);
            
            LDAPMod* mods[2];
            LDAPMod mod1;
            
            char* regValues[] = {const_cast<char*>(regInfo.c_str()), nullptr};
            mod1.mod_op = LDAP_MOD_ADD;
            mod1.mod_type = "keywords";
            mod1.mod_vals.modv_strvals = regValues;
            mods[0] = &mod1;
            mods[1] = nullptr;
            
            int result = ldap_modify_s(ldapSession, const_cast<char*>(gpoDN.c_str()), mods);
            
            if (result == LDAP_SUCCESS) {
                std::wcout << L"Registry entry tracked via LDAP" << std::endl;
            }
            
        } catch (...) {
            // Non-critical error, continue execution
        }
        
        return S_OK;
    }

    // Create registry entry in GPO (existing ADSI functionality)
    HRESULT CreateRegistryEntry(IADs* pContainer, 
                               const std::wstring& registryPath,
                               const std::wstring& valueName,
                               const std::wstring& valueData,
                               DWORD valueType) {
        HRESULT hr = S_OK;
        
        try {
            // Set registry policy attributes using IADs::Put
            VARIANT var;
            VariantInit(&var);
            
            // Set registry key path
            var.vt = VT_BSTR;
            var.bstrVal = SysAllocString(registryPath.c_str());
            hr = pContainer->Put(L"registryKey", var);
            VariantClear(&var);
            
            // Set value name
            var.vt = VT_BSTR;
            var.bstrVal = SysAllocString(valueName.c_str());
            hr = pContainer->Put(L"registryValueName", var);
            VariantClear(&var);
            
            // Set value data
            var.vt = VT_BSTR;
            var.bstrVal = SysAllocString(valueData.c_str());
            hr = pContainer->Put(L"registryValue", var);
            VariantClear(&var);
            
            // Set value type
            var.vt = VT_I4;
            var.lVal = valueType;
            hr = pContainer->Put(L"registryValueType", var);
            VariantClear(&var);
            
            // Commit changes using IADs::SetInfo
            hr = pContainer->SetInfo();
            
            if (SUCCEEDED(hr)) {
                std::wcout << L"Registry entry created: " << registryPath << L"\\" << valueName << std::endl;
            }
            
        } catch (_com_error& e) {
            std::wcout << L"Error creating registry entry: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }
        
        return hr;
    }

    // Create GPO sub-container (existing ADSI functionality)
    HRESULT CreateGPOSubContainer(IADs* pGPO, const std::wstring& containerName) {
        HRESULT hr = S_OK;
        IADsContainer* pGPOContainer = nullptr;
        IDispatch* pNewContainer = nullptr;
        
        try {
            hr = pGPO->QueryInterface(IID_IADsContainer, (void**)&pGPOContainer);
            
            if (SUCCEEDED(hr)) {
                std::wstring containerCN = L"CN=" + containerName;
                
                BSTR bstrClass = SysAllocString(L"container");
                BSTR bstrName = SysAllocString(containerCN.c_str());
                
                hr = pGPOContainer->Create(bstrClass, bstrName, &pNewContainer);
                
                SysFreeString(bstrClass);
                SysFreeString(bstrName);
            }
            
        } catch (_com_error& e) {
            hr = e.Error();
        }
        
        if (pNewContainer) pNewContainer->Release();
        if (pGPOContainer) pGPOContainer->Release();
        
        return hr;
    }

    // Enumerate existing GPOs using both ADSI and LDAP
    HRESULT EnumerateGPOs(const std::wstring& domainDN) {
        HRESULT hr = S_OK;
        
        std::wcout << L"=== Enumerating GPOs using ADSI ===" << std::endl;
        hr = EnumerateGPOsWithADSI(domainDN);
        
        if (ldapSession) {
            std::wcout << L"\n=== Enumerating GPOs using LDAP ===" << std::endl;
            hr = SearchGPOsWithLDAP(domainDN);
        }
        
        return hr;
    }

    // Enumerate GPOs using ADSI (existing functionality)
    HRESULT EnumerateGPOsWithADSI(const std::wstring& domainDN) {
        HRESULT hr = S_OK;
        IADsContainer* pContainer = nullptr;
        IEnumVARIANT* pEnum = nullptr;
        
        try {
            // Connect to Policies container
            std::wstring policiesPath = L"LDAP://CN=Policies,CN=System," + domainDN;
            hr = ADsGetObject(policiesPath.c_str(), IID_IADsContainer, (void**)&pContainer);
            
            if (SUCCEEDED(hr)) {
                // Build enumerator using ADsBuildEnumerator
                hr = ADsBuildEnumerator(pContainer, &pEnum);
                
                if (SUCCEEDED(hr)) {
                    VARIANT var;
                    ULONG lFetch = 0;
                    
                    std::wcout << L"=== Existing Group Policy Objects (ADSI) ===" << std::endl;
                    
                    // Enumerate using ADsEnumerateNext
                    while (SUCCEEDED(ADsEnumerateNext(pEnum, 1, &var, &lFetch)) && lFetch == 1) {
                        if (var.vt == VT_DISPATCH) {
                            IADs* pChild = nullptr;
                            hr = var.pdispVal->QueryInterface(IID_IADs, (void**)&pChild);
                            
                            if (SUCCEEDED(hr)) {
                                VARIANT varName, varDisplayName;
                                VariantInit(&varName);
                                VariantInit(&varDisplayName);
                                
                                // Get GPO name using IADs::Get
                                hr = pChild->Get(L"name", &varName);
                                hr = pChild->Get(L"displayName", &varDisplayName);
                                
                                if (SUCCEEDED(hr)) {
                                    std::wcout << L"GPO GUID: " << (varName.vt == VT_BSTR ? varName.bstrVal : L"N/A") << std::endl;
                                    std::wcout << L"Display Name: " << (varDisplayName.vt == VT_BSTR ? varDisplayName.bstrVal : L"N/A") << std::endl;
                                    std::wcout << L"---" << std::endl;
                                }
                                
                                VariantClear(&varName);
                                VariantClear(&varDisplayName);
                                pChild->Release();
                            }
                        }
                        VariantClear(&var);
                    }
                    
                    // Free enumerator using ADsFreeEnumerator
                    ADsFreeEnumerator(pEnum);
                }
            }
            
        } catch (_com_error& e) {
            std::wcout << L"Error enumerating GPOs: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }
        
        if (pContainer) pContainer->Release();
        
        return hr;
    }

    // Modify existing GPO properties using IADs::Get and IADs::Put
    HRESULT ModifyGPOProperties(const std::wstring& domainDN, const std::wstring& gpoGuid) {
        HRESULT hr = S_OK;
        IADs* pGPO = nullptr;
        
        try {
            // Connect to specific GPO using ADsGetObject
            std::wstring gpoPath = L"LDAP://CN=" + gpoGuid + L",CN=Policies,CN=System," + domainDN;
            hr = ADsGetObject(gpoPath.c_str(), IID_IADs, (void**)&pGPO);
            
            if (SUCCEEDED(hr)) {
                VARIANT var;
                VariantInit(&var);
                
                // Get current display name using IADs::Get
                hr = pGPO->Get(L"displayName", &var);
                if (SUCCEEDED(hr) && var.vt == VT_BSTR) {
                    std::wcout << L"Current GPO Name: " << var.bstrVal << std::endl;
                }
                VariantClear(&var);
                
                // Modify display name using IADs::Put
                var.vt = VT_BSTR;
                var.bstrVal = SysAllocString(L"Modified Registry Policy GPO");
                hr = pGPO->Put(L"displayName", var);
                VariantClear(&var);
                
                // Update version number
                var.vt = VT_I4;
                var.lVal = 2; // Increment version
                hr = pGPO->Put(L"versionNumber", var);
                VariantClear(&var);
                
                // Commit changes using IADs::SetInfo
                hr = pGPO->SetInfo();
                
                if (SUCCEEDED(hr)) {
                    std::wcout << L"GPO properties updated successfully" << std::endl;
                }
            }
            
        } catch (_com_error& e) {
            std::wcout << L"Error modifying GPO: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }
        
        if (pGPO) pGPO->Release();
        return hr;
    }

    // Delete GPO using IADsContainer::Delete
    HRESULT DeleteRegistryGPO(const std::wstring& domainDN, const std::wstring& gpoGuid) {
        HRESULT hr = S_OK;
        IADsContainer* pContainer = nullptr;
        
        try {
            // Connect to Policies container
            std::wstring policiesPath = L"LDAP://CN=Policies,CN=System," + domainDN;
            hr = ADsGetObject(policiesPath.c_str(), IID_IADsContainer, (void**)&pContainer);
            
            if (SUCCEEDED(hr)) {
                std::wstring gpoCN = L"CN=" + gpoGuid;
                
                BSTR bstrClass = SysAllocString(L"groupPolicyContainer");
                BSTR bstrName = SysAllocString(gpoCN.c_str());
                
                // Delete GPO using IADsContainer::Delete
                hr = pContainer->Delete(bstrClass, bstrName);
                
                if (SUCCEEDED(hr)) {
                    std::wcout << L"GPO deleted successfully: " << gpoGuid << std::endl;
                } else {
                    std::wcout << L"Failed to delete GPO: " << std::hex << hr << std::endl;
                }
                
                SysFreeString(bstrClass);
                SysFreeString(bstrName);
            }
            
        } catch (_com_error& e) {
            std::wcout << L"Error deleting GPO: " << e.ErrorMessage() << std::endl;
            hr = e.Error();
        }
        
        if (pContainer) pContainer->Release();
        return hr;
    }
};

int main() {
    std::wcout << L"=== Central Registry Manager - ADSI Demo ===" << std::endl;
    
    // Create manager instance
    CentralRegistryManager manager;
    
    // Example domain DN - replace with your actual domain
    std::wstring domainDN = L"DC=example,DC=com";
    std::wstring serverName = L"domain-controller.example.com"; // Replace with your DC
    
    // Initialize LDAP connection (optional - for enhanced functionality)
    HRESULT hr = manager.InitializeLDAPConnection(serverName, domainDN);
    if (FAILED(hr)) {
        std::wcout << L"Warning: LDAP connection failed, using ADSI only" << std::endl;
    }
    
    // Test menu system
    int choice = 0;
    do {
        std::wcout << L"\n=== Menu ===" << std::endl;
        std::wcout << L"1. Create new Registry GPO" << std::endl;
        std::wcout << L"2. Enumerate existing GPOs" << std::endl;
        std::wcout << L"3. Search GPOs (LDAP)" << std::endl;
        std::wcout << L"4. Modify GPO properties" << std::endl;
        std::wcout << L"5. Add registry policy to GPO" << std::endl;
        std::wcout << L"6. Delete GPO" << std::endl;
        std::wcout << L"0. Exit" << std::endl;
        std::wcout << L"Enter choice: ";
        
        std::wcin >> choice;
        
        switch (choice) {
            case 1: {
                std::wstring gpoName = L"Test Registry Policy GPO";
                std::wstring gpoGuid;
                
                std::wcout << L"Creating new GPO: " << gpoName << std::endl;
                hr = manager.CreateRegistryGPO(domainDN, gpoName, gpoGuid);
                
                if (SUCCEEDED(hr)) {
                    std::wcout << L"GPO created successfully with GUID: " << gpoGuid << std::endl;
                } else {
                    std::wcout << L"Failed to create GPO: " << std::hex << hr << std::endl;
                }
                break;
            }
            
            case 2: {
                std::wcout << L"Enumerating GPOs..." << std::endl;
                hr = manager.EnumerateGPOs(domainDN);
                break;
            }
            
            case 3: {
                std::wcout << L"Searching GPOs with LDAP..." << std::endl;
                hr = manager.SearchGPOsWithLDAP(domainDN);
                break;
            }
            
            case 4: {
                std::wstring gpoGuid;
                std::wcout << L"Enter GPO GUID (with braces): ";
                std::wcin >> gpoGuid;
                
                hr = manager.ModifyGPOProperties(domainDN, gpoGuid);
                if (SUCCEEDED(hr)) {
                    std::wcout << L"GPO modified successfully" << std::endl;
                }
                break;
            }
            
            case 5: {
                std::wstring gpoGuid;
                std::wcout << L"Enter GPO GUID (with braces): ";
                std::wcin >> gpoGuid;
                
                // Example registry policy
                std::wstring regPath = L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Test";
                std::wstring valueName = L"TestValue";
                std::wstring valueData = L"TestData";
                DWORD valueType = REG_SZ;
                
                hr = manager.AddRegistryPolicyToGPO(domainDN, gpoGuid, regPath, 
                                                   valueName, valueData, valueType);
                if (SUCCEEDED(hr)) {
                    std::wcout << L"Registry policy added successfully" << std::endl;
                }
                break;
            }
            
            case 6: {
                std::wstring gpoGuid;
                std::wcout << L"Enter GPO GUID to delete (with braces): ";
                std::wcin >> gpoGuid;
                
                hr = manager.DeleteRegistryGPO(domainDN, gpoGuid);
                break;
            }
            
            case 0:
                std::wcout << L"Exiting..." << std::endl;
                break;
                
            default:
                std::wcout << L"Invalid choice!" << std::endl;
                break;
        }
        
    } while (choice != 0);
    
    std::wcout << L"Program completed." << std::endl;
    return 0;
}