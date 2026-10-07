package com.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class UserServiceTest {

    @Test
    void testIsValidUsername_valid() {
        assertTrue(UserService.isValidUsername("john_doe"));
    }

    @Test
    void testIsValidUsername_null() {
        assertFalse(UserService.isValidUsername(null));
    }

    @Test
    void testIsValidUsername_empty() {
        assertFalse(UserService.isValidUsername(""));
    }

    @Test
    void testIsValidUsername_tooShort() {
        assertFalse(UserService.isValidUsername("ab"));
    }

    @Test
    void testSanitizeInput_removesSpecialChars() {
        assertEquals("hello world", UserService.sanitizeInput("hello! world@#$"));
    }

    @Test
    void testSanitizeInput_null() {
        assertEquals("", UserService.sanitizeInput(null));
    }

    @Test
    void testSanitizeInput_normal() {
        assertEquals("hello", UserService.sanitizeInput("hello"));
    }

    @Test
    void testIsValidEmail_valid() {
        assertTrue(UserService.isValidEmail("user@example.com"));
    }

    @Test
    void testIsValidEmail_null() {
        assertFalse(UserService.isValidEmail(null));
    }

    @Test
    void testIsValidEmail_empty() {
        assertFalse(UserService.isValidEmail(""));
    }

    @Test
    void testIsValidEmail_noAt() {
        assertFalse(UserService.isValidEmail("userexample.com"));
    }

    @Test
    void testFormatUsername_normal() {
        assertEquals("john", UserService.formatUsername("  JOHN  "));
    }

    @Test
    void testFormatUsername_null() {
        assertEquals("", UserService.formatUsername(null));
    }

    @Test
    void testIsAdminUser_admin() {
        assertTrue(UserService.isAdminUser("admin"));
    }

    @Test
    void testIsAdminUser_root() {
        assertTrue(UserService.isAdminUser("root"));
    }

    @Test
    void testIsAdminUser_regular() {
        assertFalse(UserService.isAdminUser("john"));
    }

    @Test
    void testIsAdminUser_null() {
        assertFalse(UserService.isAdminUser(null));
    }

    @Test
    void testGetUserAccessLevel_admin() {
        assertEquals(3, UserService.getUserAccessLevel("admin"));
    }

    @Test
    void testGetUserAccessLevel_editor() {
        assertEquals(2, UserService.getUserAccessLevel("editor"));
    }

    @Test
    void testGetUserAccessLevel_viewer() {
        assertEquals(1, UserService.getUserAccessLevel("viewer"));
    }

    @Test
    void testGetUserAccessLevel_unknown() {
        assertEquals(0, UserService.getUserAccessLevel("guest"));
    }

    @Test
    void testGetUserAccessLevel_null() {
        assertEquals(0, UserService.getUserAccessLevel(null));
    }
}
