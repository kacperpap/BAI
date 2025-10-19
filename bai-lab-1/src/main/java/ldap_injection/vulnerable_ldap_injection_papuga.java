package ldap_injection;

import com.unboundid.ldap.sdk.*;

/*
 * vulnerable_ldap_injection_papuga pokazuje typowe błędy:
 * - bezpośrednia konkatenacja danych wejściowych do filtra LDAP
 * - brak walidacji/escape
 * - brak TLS / brak timeoutów (w przykładzie to uproszczenie)
 * - logowanie wrażliwych danych (np. zwracanie szczegółów błędu i filtra użytkownikowi)
 *
 */

class vulnerable_ldap_injection_papuga implements LDAPClient {

    private final String ldapHost;
    private final int ldapPort;
    private final String baseDN;
    private final String serviceBindDN;
    private final String servicePassword;

    public vulnerable_ldap_injection_papuga(String ldapHost, int ldapPort, String baseDN, String serviceBindDN,
            String servicePassword) {
        this.ldapHost = ldapHost;
        this.ldapPort = ldapPort;
        this.baseDN = baseDN;
        this.serviceBindDN = serviceBindDN;
        this.servicePassword = servicePassword;
    }

    @Override
    public boolean authenticate(String userInput, String password) throws Exception {
        String filter = buildFilterForUser(userInput, password);
        LDAPConnection connection = null;
        try {
            connection = new LDAPConnection(ldapHost, ldapPort, serviceBindDN, servicePassword);

            SearchRequest searchRequest = new SearchRequest(
                    baseDN,               // Base DN -- Specifies the base DN for the search. Only entries at or below this location in the server (based on the scope) will be considered potential matches.
                    SearchScope.SUB,      // Scope -- Specifies the range of entries relative to the base DN that may be considered potential matches
                    filter);              // Filter -- Specifies the criteria for determining which entries should be returned.

            SearchResult searchResult = connection.search(searchRequest);

            return !searchResult.getSearchEntries().isEmpty();

        } catch (LDAPException e) {
            System.err.println("LDAP error: " + e.getMessage());
            System.err.println("Used filter: " + filter);
            throw new Exception("LDAP error: " + e.getMessage() + " | Used filter: " + filter, e);
        } finally {
            if (connection != null)
                connection.close();
        }
    }

    @Override
    public String buildFilterForUser(String userInput, String password) {
        return "(&(cn=" + userInput + ")(userPassword=" + password + "))";
    }

    @Override
    public String buildFilterForUser(String userInput) {
        throw new UnsupportedOperationException("Not implemented in this example");
    }
}
