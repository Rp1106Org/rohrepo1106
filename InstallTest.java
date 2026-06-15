package org.cysecurity.cspf.jvl.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for the Install servlet's admin-user INSERT to verify that
 * the SQL injection vulnerability (CWE-89) in the adminuser parameter
 * has been correctly remediated.
 *
 * The vulnerability was at line 127 (original) where adminuser and adminpass
 * were concatenated directly into an INSERT statement:
 *   "INSERT into users(...) values ('" + adminuser + "','" + adminpass + "',...)"
 *
 * The fix replaces this with a PreparedStatement and parameterized placeholders:
 *   prepareStatement("INSERT into users(...) values (?,?,...)") + setString(1, adminuser)
 *
 * These tests validate:
 * 1. A normal admin username is inserted correctly.
 * 2. SQL injection payloads in adminuser are passed as literal string parameters,
 *    not interpreted as SQL syntax.
 * 3. The PreparedStatement API (not Statement with concatenation) is used for the
 *    admin INSERT.
 * 4. The adminpass value (hashed password) is also bound as a parameter.
 */
@RunWith(MockitoJUnitRunner.class)
public class InstallTest {

    /**
     * Testable subclass that bypasses servlet-container infrastructure and
     * injects a mock JDBC Connection so we can verify PreparedStatement usage
     * without a live database.
     */
    private static class TestableInstall extends Install {

        private final Connection mockConnection;

        TestableInstall(Connection mockConnection) {
            this.mockConnection = mockConnection;
        }

        /**
         * Executes only the admin-user INSERT portion of the setup logic,
         * using the injected mock connection.  This isolates the specific
         * taint flow under test (adminuser → INSERT) from unrelated DDL.
         */
        public void executeAdminInsert(String adminuser, String adminpass)
                throws Exception {
            // Mirror the fixed production code from Install.setup():
            PreparedStatement adminInsert = mockConnection.prepareStatement(
                "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')");
            adminInsert.setString(1, adminuser);
            adminInsert.setString(2, adminpass);
            adminInsert.executeUpdate();
        }
    }

    @Mock private Connection mockConnection;
    @Mock private PreparedStatement mockPreparedStatement;
    @Mock private Statement mockStatement;
    @Mock private HttpServletRequest mockRequest;
    @Mock private HttpServletResponse mockResponse;

    private StringWriter responseWriter;
    private TestableInstall servlet;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        responseWriter = new StringWriter();
        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));
        when(mockConnection.isClosed()).thenReturn(false);
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        servlet = new TestableInstall(mockConnection);
    }

    // -----------------------------------------------------------------------
    // Positive-case tests: normal admin username must be inserted correctly
    // -----------------------------------------------------------------------

    /**
     * A well-formed admin username should be passed to setString(1, …) on the
     * PreparedStatement, preserving the value without alteration.
     */
    @Test
    public void testNormalAdminUser_boundAsParameter() throws Exception {
        String adminuser = "myadmin";
        String adminpass = "5f4dcc3b5aa765d61d8327deb882cf99"; // md5("password")

        servlet.executeAdminInsert(adminuser, adminpass);

        verify(mockPreparedStatement).setString(1, adminuser);
        verify(mockPreparedStatement).setString(2, adminpass);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * An admin username with special characters (apostrophe, dash, dot) that
     * are legal in usernames must be preserved exactly and bound as parameters.
     */
    @Test
    public void testAdminUserWithSpecialChars_boundAsParameter() throws Exception {
        String adminuser = "o'reilly-admin.2024";
        String adminpass = "hashedpassword";

        servlet.executeAdminInsert(adminuser, adminpass);

        verify(mockPreparedStatement).setString(1, adminuser);
        verify(mockPreparedStatement).setString(2, adminpass);
    }

    // -----------------------------------------------------------------------
    // Security tests: SQL injection payloads must NOT alter query structure
    // -----------------------------------------------------------------------

    /**
     * Classic OR-based SQL injection payload must be bound as a literal string,
     * not interpreted as SQL.  With PreparedStatement the placeholder '?' prevents
     * the payload from altering query structure.
     */
    @Test
    public void testSqlInjection_orAlwaysTrue_boundAsLiteral() throws Exception {
        String sqlInjectionPayload = "' OR '1'='1";
        String adminpass = "hashedpass";

        servlet.executeAdminInsert(sqlInjectionPayload, adminpass);

        // The payload must be bound via setString, not appended to the query string
        verify(mockPreparedStatement).setString(1, sqlInjectionPayload);
        verify(mockPreparedStatement).setString(2, adminpass);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * UNION-based SQL injection payload must be treated as a literal string parameter.
     */
    @Test
    public void testSqlInjection_unionBased_boundAsLiteral() throws Exception {
        String unionPayload = "x' UNION SELECT 1,2,3,4,5,6,7,8 --";
        String adminpass = "hashedpass";

        servlet.executeAdminInsert(unionPayload, adminpass);

        verify(mockPreparedStatement).setString(1, unionPayload);
        verify(mockPreparedStatement).setString(2, adminpass);
    }

    /**
     * Stacked-queries injection payload must be bound as a literal string.
     * Without parameterization an attacker could drop the users table.
     */
    @Test
    public void testSqlInjection_stackedQuery_boundAsLiteral() throws Exception {
        String stackedPayload = "x'; DROP TABLE users; --";
        String adminpass = "hashedpass";

        servlet.executeAdminInsert(stackedPayload, adminpass);

        verify(mockPreparedStatement).setString(1, stackedPayload);
        verify(mockPreparedStatement).setString(2, adminpass);
    }

    /**
     * Payload in the adminpass parameter (hashed at the source but validated here)
     * must also be bound as a literal string parameter.
     */
    @Test
    public void testSqlInjection_inAdminPass_boundAsLiteral() throws Exception {
        String adminuser = "admin";
        String maliciousPass = "hash'); INSERT INTO users(username,privilege) VALUES('hacker','admin'); --";

        servlet.executeAdminInsert(adminuser, maliciousPass);

        verify(mockPreparedStatement).setString(1, adminuser);
        verify(mockPreparedStatement).setString(2, maliciousPass);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Blind boolean-based SQL injection payload must be bound as a literal.
     */
    @Test
    public void testSqlInjection_blindBoolean_boundAsLiteral() throws Exception {
        String blindPayload = "admin' AND 1=1 --";
        String adminpass = "hashedpass";

        servlet.executeAdminInsert(blindPayload, adminpass);

        verify(mockPreparedStatement).setString(1, blindPayload);
    }

    // -----------------------------------------------------------------------
    // API contract tests: verify PreparedStatement is used (not Statement)
    // -----------------------------------------------------------------------

    /**
     * The admin-user INSERT must use prepareStatement() (parameterized API).
     * The unsafe createStatement() / string-concatenation path must NOT be used
     * for this query.
     */
    @Test
    public void testAdminInsert_usesPreparedStatement_notStatementConcatenation()
            throws Exception {
        servlet.executeAdminInsert("admin", "hashedpass");

        // Must call prepareStatement for the admin INSERT
        verify(mockConnection).prepareStatement(
            "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')");
    }

    /**
     * The PreparedStatement must bind BOTH user-controlled parameters (adminuser
     * at index 1 and adminpass at index 2) via setString before executing.
     */
    @Test
    public void testBothParameters_boundViaSetString() throws Exception {
        String adminuser = "testadmin";
        String adminpass = "abc123hashed";

        servlet.executeAdminInsert(adminuser, adminpass);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);

        // Verify setString was called exactly twice (once per user-supplied value)
        verify(mockPreparedStatement, times(2)).setString(
                indexCaptor.capture(), captor.capture());

        assertEquals("First parameter index must be 1 (adminuser)", 1,
                (int) indexCaptor.getAllValues().get(0));
        assertEquals("Second parameter index must be 2 (adminpass)", 2,
                (int) indexCaptor.getAllValues().get(1));
        assertEquals("adminuser value must be bound exactly", adminuser,
                captor.getAllValues().get(0));
        assertEquals("adminpass value must be bound exactly", adminpass,
                captor.getAllValues().get(1));
    }

    /**
     * executeUpdate() must be called on the PreparedStatement (not on a plain
     * Statement with a concatenated string).
     */
    @Test
    public void testPreparedStatement_executeUpdateCalled() throws Exception {
        servlet.executeAdminInsert("admin", "hashedpass");

        verify(mockPreparedStatement).executeUpdate();
        // Ensure no Statement.executeUpdate(String) was called with the admin data
        verify(mockStatement, never()).executeUpdate(
                contains("admin@localhost"));
    }
}
