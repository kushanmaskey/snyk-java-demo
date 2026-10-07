package com.example;

import org.junit.jupiter.api.Test;

class AppTest {

    @Test
    void testMainNoArgs() {
        App.main(new String[]{});
    }

    @Test
    void testMainWithArgs() {
        App.main(new String[]{"testuser"});
    }

    @Test
    void testGetUserData() {
        App.getUserData("testuser");
    }

    @Test
    void testExecuteUserCommand() {
        App.executeUserCommand("localhost");
    }
}
