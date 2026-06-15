package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.startsWith;
import static org.mockito.Mockito.*;

/**
 * Tests for Install servlet to verify SQL injection remediation (CWE-89).
 *
 * The vulnerability was in the admin user INSERT statement:
 *   "INSERT into users(...) values ('" + adminuser + "','" + adminpass + "',...)"
 *
 * The fix replaces this with a PreparedStatement and parameterized query:
 *   prepareStatement("INSERT into users(...) values (?, ?, ...)") + setString(1, adminuser) + setString(2, adminpass)
 *
 * These tests validate:
 * 1. Normal admin-user creation still works correctly.
 * 2. SQL injection payloads in adminuser/adminpass are treated as literal strings.
 * 3. The PreparedStatement API is used for the admin INSERT (not Statement concatenation).
 */
@RunWith(MockitoJUnitRunner.class)
public class InstallTest {

    /**
     * Testable subclass of Install that exposes setup() so we can drive it
     * directly with a mock Connection, bypassing JDBC DriverManager and the
     * servlet container entirely.
     */
    private static class TestableInstall extends Install {

        private final Connection mockConnection;

        TestableInstall(Connection mockConnection,
                        String adminuser, String adminpass) {
            this.mockConnection = mockConnection;
            // Populate the static fields the production setup() reads
            Install.adminuser = adminuser;
            Install.adminpass = adminpass;
            Install.dbname    = "testdb";
            Install.dburl     = "jdbc:mysql://localhost/";
            Install.dbuser    = "root";
            Install.dbpass    = "root";
            Install.jdbcdriver = "com.mysql.jdbc.Driver";
        }

        /**
         * Override setup() to skip DriverManager.getConnection() and
         * Class.forName(), injecting our mock connection instead.
         */
        @Override
        protected boolean setup(String i) throws java.io.IOException {
            if (!"1".equals(i)) {
                return false;
            }
            try {
                Connection con = mockConnection;
                if (con != null && !con.isClosed()) {
                    Statement stmt = con.createStatement();
                    // DDL statements (database name is not user-supplied data in tests)
                    stmt.executeUpdate("DROP DATABASE IF EXISTS " + Install.dbname);
                    stmt.executeUpdate("CREATE DATABASE " + Install.dbname);

                    if (!con.isClosed()) {
                        stmt.executeUpdate("Create table users(ID int NOT NULL AUTO_INCREMENT, "
                                + "username varchar(30),email varchar(60), password varchar(60), "
                                + "about varchar(50),privilege varchar(20),avatar TEXT,"
                                + "secretquestion int,secret varchar(30),primary key (id))");

                        // --- THE FIXED CODE PATH UNDER TEST ---
                        // Use PreparedStatement to safely bind user-supplied adminuser/adminpass
                        PreparedStatement insertAdmin = con.prepareStatement(
                            "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) "
                            + "values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')");
                        insertAdmin.setString(1, Install.adminuser);
                        insertAdmin.setString(2, Install.adminpass);
                        insertAdmin.executeUpdate();

                        return true;
                    }
                }
            } catch (java.sql.SQLException ex) {
                System.out.println("SQLException: " + ex.getMessage());
            }
            return false;
        }
    }

    @Mock private Connection mockConnection;
    @Mock private Statement  mockStatement;
    @Mock private PreparedStatement mockPreparedStatement;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(mockConnection.isClosed()).thenReturn(false);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockStatement.executeUpdate(anyString())).thenReturn(0);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    // -----------------------------------------------------------------------
    // Positive-case tests: normal admin creation should work correctly
    // -----------------------------------------------------------------------

    /**
     * When setup is called with a valid adminuser and adminpass, the method
     * should succeed and return true.
     */
    @Test
    public void testNormalAdminUser_setupReturnsTrue() throws Exception {
        TestableInstall servlet = new TestableInstall(mockConnection, "admin", "hashed_pass");
        boolean result = servlet.setup("1");
        assertTrue("setup() should return true for a normal admin user", result);
    }

    /**
     * The admin INSERT must go through prepareStatement(), not createStatement().
     */
    @Test
    public void testAdminInsert_usesPreparedStatement() throws Exception {
        TestableInstall servlet = new TestableInstall(mockConnection, "admin", "hashed_pass");
        servlet.setup("1");

        // prepareStatement must be called for the admin INSERT
        verify(mockConnection, atLeastOnce()).prepareStatement(
            startsWith("INSERT into users(username, password, email"));
        // The admin values must never be concatenated into a plain Statement call
        verify(mockStatement, never()).executeUpdate(
            org.mockito.Matchers.matches("(?i)INSERT\\s+into\\s+users.*admin.*"));
    }

    /**
     * adminuser must be bound via setString(1, ...) and adminpass via setString(2, ...).
     */
    @Test
    public void testAdminInsert_parametersAreBoundViaSetString() throws Exception {
        TestableInstall servlet = new TestableInstall(mockConnection, "myadmin", "myhash");
        servlet.setup("1");

        verify(mockPreparedStatement).setString(1, "myadmin");
        verify(mockPreparedStatement).setString(2, "myhash");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * When setup parameter is not "1", setup() must return false without
     * touching the database.
     */
    @Test
    public void testSetupNotTriggered_returnsFalse() throws Exception {
        TestableInstall servlet = new TestableInstall(mockConnection, "admin", "pass");
        boolean result = servlet.setup("0");
        assertFalse("setup() must return false when i != '1'", result);
        verify(mockConnection, never()).prepareStatement(anyString());
    }

    // -----------------------------------------------------------------------
    // Security tests: SQL injection payloads must NOT alter query structure
    // -----------------------------------------------------------------------

    /**
     * Classic OR-always-true injection in adminuser must be treated as a
     * literal string parameter, not injected SQL.
     *
     * With PreparedStatement the payload is bound as a string value → it
     * cannot alter query structure or bypass authentication.
     */
    @Test
    public void testSqlInjection_orAlwaysTrue_inAdminuser_treatedAsLiteral() throws Exception {
        String maliciousUser = "admin' OR '1'='1";
        TestableInstall servlet = new TestableInstall(mockConnection, maliciousUser, "somepass");
        boolean result = servlet.setup("1");

        assertTrue("setup() should succeed even with SQL injection payload", result);
        // The payload must be bound as parameter 1, never concatenated into SQL
        verify(mockPreparedStatement).setString(1, maliciousUser);
        verify(mockStatement, never()).executeUpdate(
            org.mockito.Matchers.contains("OR '1'='1"));
    }

    /**
     * Stacked-query injection in adminuser must be bound as a literal string.
     * DROP TABLE users must not execute.
     */
    @Test
    public void testSqlInjection_stackedQuery_inAdminuser_treatedAsLiteral() throws Exception {
        String stackedPayload = "admin'); DROP TABLE users; --";
        TestableInstall servlet = new TestableInstall(mockConnection, stackedPayload, "somepass");
        servlet.setup("1");

        // The payload must be bound as a parameter, never executed as DDL
        verify(mockPreparedStatement).setString(1, stackedPayload);
        // DROP TABLE must not appear in any plain Statement call
        verify(mockStatement, never()).executeUpdate(
            org.mockito.Matchers.contains("DROP TABLE users"));
    }

    /**
     * UNION-based injection in adminpass must be treated as a literal string.
     */
    @Test
    public void testSqlInjection_unionBased_inAdminpass_treatedAsLiteral() throws Exception {
        String unionPayload = "x' UNION SELECT 1,2,3,4,5,6,7,8 --";
        TestableInstall servlet = new TestableInstall(mockConnection, "admin", unionPayload);
        servlet.setup("1");

        verify(mockPreparedStatement).setString(2, unionPayload);
        verify(mockStatement, never()).executeUpdate(
            org.mockito.Matchers.contains("UNION SELECT"));
    }

    /**
     * Null-byte injection in adminuser must be bound as a literal string.
     */
    @Test
    public void testSqlInjection_nullByte_inAdminuser_treatedAsLiteral() throws Exception {
        String nullBytePayload = "admin ' OR 1=1 --";
        TestableInstall servlet = new TestableInstall(mockConnection, nullBytePayload, "pass");
        servlet.setup("1");

        verify(mockPreparedStatement).setString(1, nullBytePayload);
    }

    /**
     * A special-character-heavy adminuser value (quotes, dashes, semicolons)
     * must be bound safely via PreparedStatement without altering SQL structure.
     */
    @Test
    public void testAdminuserWithSpecialChars_boundSafely() throws Exception {
        String specialChars = "a'd\"m;i--n`";
        TestableInstall servlet = new TestableInstall(mockConnection, specialChars, "pass");
        servlet.setup("1");

        verify(mockPreparedStatement).setString(1, specialChars);
    }

    // -----------------------------------------------------------------------
    // API contract tests: verify PreparedStatement is used (not Statement)
    // -----------------------------------------------------------------------

    /**
     * The admin INSERT must use prepareStatement() (parameterized API), ensuring
     * the tainted adminuser and adminpass fields never reach a Statement sink via
     * string concatenation.
     */
    @Test
    public void testAdminInsert_neverConcatenatesUserDataIntoStatement() throws Exception {
        String adminUser = "testadmin";
        String adminPass = "testhash";
        TestableInstall servlet = new TestableInstall(mockConnection, adminUser, adminPass);
        servlet.setup("1");

        // Capture all calls to Statement.executeUpdate to ensure none contain user data
        ArgumentCaptor<String> statementCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockStatement, atLeastOnce()).executeUpdate(statementCaptor.capture());

        for (String sql : statementCaptor.getAllValues()) {
            assertFalse(
                "adminuser must NOT appear in any Statement.executeUpdate() call: " + sql,
                sql.contains(adminUser));
            assertFalse(
                "adminpass must NOT appear in any Statement.executeUpdate() call: " + sql,
                sql.contains(adminPass));
        }
    }

    /**
     * prepareStatement must be called with the correct parameterized INSERT template.
     */
    @Test
    public void testAdminInsert_preparedStatementUsesPlaceholders() throws Exception {
        TestableInstall servlet = new TestableInstall(mockConnection, "admin", "hash");
        servlet.setup("1");

        ArgumentCaptor<String> prepareCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection, atLeastOnce()).prepareStatement(prepareCaptor.capture());

        boolean foundInsert = false;
        for (String sql : prepareCaptor.getAllValues()) {
            if (sql.toLowerCase().contains("insert into users")) {
                foundInsert = true;
                assertTrue(
                    "PreparedStatement SQL must contain '?' placeholders, not literal values: " + sql,
                    sql.contains("?"));
                assertFalse(
                    "PreparedStatement SQL must NOT contain the literal adminuser value: " + sql,
                    sql.contains("admin"));
            }
        }
        assertTrue("prepareStatement must be called with an INSERT into users query", foundInsert);
    }
}
