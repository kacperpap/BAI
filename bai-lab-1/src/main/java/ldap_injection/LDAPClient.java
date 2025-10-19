package ldap_injection;

public interface LDAPClient {
 /**
     * Próba uwierzytelnienia użytkownika: zwykle bind lub search+bind w zależności od mechanizmu.
     *
     * @param userInput UID / username wprowadzony przez użytkownika
     * @param password hasło użytkownika
     * @return true jeśli operacja zakończyła się sukcesem (w demonstracji może zwracać symulację)
     * @throws Exception w przypadku błędów połączenia / walidacji
     */

    // metoda niebezpieczne - bind za pomoca filtra user+pass
    boolean authenticate(String userInput, String password) throws Exception;

    /**
     * Utility dla testów: zwraca string filtra jaki zostanie użyty (ułatwia porównanie bez konieczności realnego połączenia).
     */
    String buildFilterForUser(String userInput) throws Exception;

    String buildFilterForUser(String userInput, String password);
}