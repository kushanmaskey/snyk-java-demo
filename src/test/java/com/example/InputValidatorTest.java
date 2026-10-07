package com.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class InputValidatorTest {

    @Test
    void testIsNullOrEmpty_null() {
        assertTrue(InputValidator.isNullOrEmpty(null));
    }

    @Test
    void testIsNullOrEmpty_empty() {
        assertTrue(InputValidator.isNullOrEmpty(""));
    }

    @Test
    void testIsNullOrEmpty_blank() {
        assertTrue(InputValidator.isNullOrEmpty("   "));
    }

    @Test
    void testIsNullOrEmpty_valid() {
        assertFalse(InputValidator.isNullOrEmpty("hello"));
    }

    @Test
    void testIsNumeric_integer() {
        assertTrue(InputValidator.isNumeric("123"));
    }

    @Test
    void testIsNumeric_decimal() {
        assertTrue(InputValidator.isNumeric("12.5"));
    }

    @Test
    void testIsNumeric_negative() {
        assertTrue(InputValidator.isNumeric("-42"));
    }

    @Test
    void testIsNumeric_null() {
        assertFalse(InputValidator.isNumeric(null));
    }

    @Test
    void testIsNumeric_letters() {
        assertFalse(InputValidator.isNumeric("abc"));
    }

    @Test
    void testIsWithinLength_valid() {
        assertTrue(InputValidator.isWithinLength("hello", 3, 10));
    }

    @Test
    void testIsWithinLength_tooShort() {
        assertFalse(InputValidator.isWithinLength("hi", 3, 10));
    }

    @Test
    void testIsWithinLength_tooLong() {
        assertFalse(InputValidator.isWithinLength("hello world!", 3, 10));
    }

    @Test
    void testIsWithinLength_null() {
        assertFalse(InputValidator.isWithinLength(null, 3, 10));
    }

    @Test
    void testTruncate_withinLimit() {
        assertEquals("hello", InputValidator.truncate("hello", 10));
    }

    @Test
    void testTruncate_exceedsLimit() {
        assertEquals("hello", InputValidator.truncate("hello world", 5));
    }

    @Test
    void testTruncate_null() {
        assertEquals("", InputValidator.truncate(null, 5));
    }

    @Test
    void testContainsOnlyAlpha_valid() {
        assertTrue(InputValidator.containsOnlyAlpha("hello"));
    }

    @Test
    void testContainsOnlyAlpha_withNumbers() {
        assertFalse(InputValidator.containsOnlyAlpha("hello1"));
    }

    @Test
    void testContainsOnlyAlpha_null() {
        assertFalse(InputValidator.containsOnlyAlpha(null));
    }

    @Test
    void testMaskSensitiveData_normal() {
        assertEquals("jo****hn", InputValidator.maskSensitiveData("johndoehn"));
    }

    @Test
    void testMaskSensitiveData_short() {
        assertEquals("****", InputValidator.maskSensitiveData("ab"));
    }

    @Test
    void testMaskSensitiveData_null() {
        assertEquals("", InputValidator.maskSensitiveData(null));
    }

    @Test
    void testMaskSensitiveData_empty() {
        assertEquals("", InputValidator.maskSensitiveData(""));
    }
}
