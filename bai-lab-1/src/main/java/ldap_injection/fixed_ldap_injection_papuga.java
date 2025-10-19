package ldap_injection;

import java.text.Normalizer;
import java.util.regex.Pattern;

import com.unboundid.ldap.sdk.*;

/*
 * fixed_ldap_injection_papuga stosuje:
 * - UnboundID LDAP SDK (bezpośrednie API do tworzenia parametrów filtrów)
 * - Filter.createEqualityFilter(attr, value) -> automatyczne prawidłowe escape wartości dla filtra (RFC4515)
 * - Allow-list input validation (regex), normalizacja Unicode (NFC)
 * - Krótkie timeouty i limit wyników (limit wyników w SearchRequest)
 * - TLS (LDAPS lub StartTLS) — na potrzeby przykładu pomijamy konfigurację SSL
 * - Least privilege: używamy konta serwisowego z minimalnymi uprawnieniami - konfiguracja po stronie LDAP
 * - Nie logujemy haseł ani danych wrażliwych
 */

public class fixed_ldap_injection_papuga implements LDAPClient {
    private final String ldapHost;
    private final int ldapPort;
    private final String baseDN;
    private final String serviceBindDN;
    private final String servicePassword;
    private final int connectTimeoutMillis = 5_000;

    // Polityka allow-list dla UID / username: tylko litery, cyfry, ".", "-", "_" i max 64 znaki.
    private static final Pattern UID_ALLOWLIST = Pattern.compile("^[\\p{Alnum}._-]{1,64}$");

    public fixed_ldap_injection_papuga(String ldapHost, int ldapPort, String baseDN, String serviceBindDN, String servicePassword) {
        this.ldapHost = ldapHost;
        this.ldapPort = ldapPort;
        this.baseDN = baseDN;
        this.serviceBindDN = serviceBindDN;
        this.servicePassword = servicePassword;
    }

    @Override
    public boolean authenticate(String userInput, String password) throws Exception {
        String normalized = normalizeAndValidateUserInput(userInput);

        LDAPConnectionOptions opts = new LDAPConnectionOptions();
        opts.setConnectTimeoutMillis(connectTimeoutMillis);

        LDAPConnection serviceConn = null;
        try {
            // Połączenie bez SSL (na potrzeby przykładu)
            serviceConn = new LDAPConnection(opts, ldapHost, ldapPort, serviceBindDN, servicePassword);

            Filter searchFilter = Filter.createEqualityFilter("uid", normalized);

            SearchRequest req = new SearchRequest(baseDN, SearchScope.SUB, searchFilter);
            req.setSizeLimit(1);
            req.setTimeLimitSeconds(5);
            
            SearchResult sr = serviceConn.search(req);

            if (sr.getEntryCount() != 1) {
                return false;
            }

            String userDN = sr.getSearchEntries().get(0).getDN();

            LDAPConnection userConn = null;
            try {
                userConn = new LDAPConnection(opts, ldapHost, ldapPort);
                BindResult bindResult = userConn.bind(userDN, password);
                return bindResult.getResultCode() == ResultCode.SUCCESS;
            } finally {
                if (userConn != null) userConn.close();
            }

        } finally {
            if (serviceConn != null) serviceConn.close();
        }
    }

    private String normalizeAndValidateUserInput(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Empty input");
        }

        String normalized = Normalizer.normalize(input, Normalizer.Form.NFC).trim();

        if (normalized.length() == 0 || normalized.length() > 64) {
            throw new IllegalArgumentException("Invalid input length");
        }

        if (!UID_ALLOWLIST.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Invalid characters in input");
        }

        return normalized;
    }

    @Override
    public String buildFilterForUser(String userInput) throws Exception {
        String normalized = normalizeAndValidateUserInput(userInput);
        Filter f = Filter.createEqualityFilter("uid", normalized);
        return f.toString();
    }

    @Override
    public String buildFilterForUser(String userInput, String password) {
        throw new UnsupportedOperationException("Unimplemented method 'buildFilterForUser'");
    }
}
