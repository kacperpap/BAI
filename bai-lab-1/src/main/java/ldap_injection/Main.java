package ldap_injection;

import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {

        String host = "ldap.example.com";
        int port = 636; // 636 = LDAPS, 389 = ldap (niezalecane bez TLS)
        String baseDN = "ou=users,dc=example,dc=com";
        String serviceBindDN = "cn=service-account,dc=example,dc=com";
        String servicePassword = "servicePassword";

        vulnerable_ldap_injection_papuga unsafe = new vulnerable_ldap_injection_papuga(host, port, baseDN, serviceBindDN, servicePassword);
        fixed_ldap_injection_papuga safe = new fixed_ldap_injection_papuga(host, port, baseDN, serviceBindDN, servicePassword);

        // Testowe pary login + hasło
        List<String[]> testCredentials = Arrays.asList(
            new String[]{"alice", "password123"},
            new String[]{"bob*)(|(uid=*))", "pass"},
            new String[]{"*)(cn=*))(|(cn=*", "pw"},
            new String[]{"john)(|(objectClass=*))", "pw"},
            new String[]{"valid.user-name_123", "secret"},
            new String[]{"*)(cn=*))(|(cn=*", "pw"}
        );

        System.out.println("==== Porównanie filtrów (unsafe vs safe) ====");
        for (String[] creds : testCredentials) {
            String login = creds[0];
            String password = creds[1];
            try {
                String unsafeFilter = unsafe.buildFilterForUser(login, password);
                String safeFilter = safe.buildFilterForUser(login);
                System.out.println("Input: login='" + login + "', password='" + password + "'");
                System.out.println("  Unsafe filter: " + unsafeFilter);
                System.out.println("  Safe filter:   " + safeFilter);
                System.out.println("  -> Safe vs Unsafe różnica: " + (unsafeFilter.equals(safeFilter) ? "brak" : "różne"));
            } catch (Exception ex) {
                System.out.println("Input: login='" + login + "', password='" + password);
                String unsafeFilter = unsafe.buildFilterForUser(login, password);
                System.out.println("  Unsafe filter: " + unsafeFilter);
                System.out.println("  Safe filter:   " + "-> Safe build failed: " + ex.getMessage());
            }
            System.out.println();
        }

        System.out.println("==== Proste testy walidacji (czy safe zgłasza błąd dla złośliwych inputów) ====");
        for (String[] creds : testCredentials) {
            String login = creds[0];
            boolean unsafeWouldAllow = true; // unsafe zawsze 'zbuduje' filtr
            boolean safeAllows;
            try {
                safe.buildFilterForUser(login);
                safeAllows = true;
            } catch (IllegalArgumentException iae) {
                safeAllows = false;
            }
            System.out.printf("Input: %-30s | unsafe: %s | safe: %s%n", login, unsafeWouldAllow ? "ALLOW" : "DENY", safeAllows ? "ALLOW" : "DENY");
        }

    }
}
